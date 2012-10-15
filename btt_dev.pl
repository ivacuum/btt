#!/usr/bin/perl -T
#
# @package bt.ivacuum.ru
# @copyright (c) 2012 vacuum
#
use strict;
no strict 'vars';

use Cache::Memcached::Fast;
use DBI ();
use Digest::SHA1 qw(sha1_hex);
use EV;
use IO::Socket::INET qw(IPPROTO_TCP TCP_NODELAY SO_LINGER SO_REUSEADDR SOL_SOCKET);
use JSON qw(encode_json to_json);

require './functions.plib';

# Отключение буферизации
$| = 1;

#
# Настройки
#
$db_host = '';
$db_name = '';
$db_user = '';
$db_pass = '';

$s_ip    = '0.0.0.0';
$s_port  = 2760;

$g_accept_interval    = 30;      # 30 сек
$g_accepted           = 0;
$g_announce_interval  = 300;     # 5 минут
$g_auth_key_length    = 10;      # 10 символов
$g_complete_count     = 0;       # 0 закачек
$g_cron_interval      = 15;      # 15 секунд
$g_debug              = 1;
$g_expiration_time    = 3000;    # 50 минут
$g_max_leeching       = 8;       # 8 закачек
$g_max_numwant        = 200;     # 200 пиров
$g_min_numwant        = 50;      # 50 пиров
$g_rejected           = 0;       # 0 запросов
$g_snatch_delay       = 1296000; # 15 дней
$g_starttime          = $^T;
$g_timebonus_interval = 10800;   # 3 часа

# Особенные настройки для разрабатываемой версии
if( $0 =~ /_dev/ ) {
  use Data::Dumper;
  use Devel::Size qw(size total_size);
  
  $Devel::Size::warn = 0;

  $g_announce_interval = 60;
  $g_debug             = 2;
  $s_port++;

  &print_event('INFO', 'Запущена разрабатываемая версия');
}

$g_dlstatus_buffer = '';
$g_peers_buffer    = '';

%g_files;
%g_peers;
$g_timers = {
  'files_read' => $^T,
  'users_read' => $^T
};
%g_topics;
%g_uids;
%g_users;

# Подключение к БД
&db_connect();

# Принудительное завершение работы (Ctrl+C)
my $sigint = EV::signal 'INT', sub {
  &tracker_shutdown('SIGINT');
};

# Принудительное завершение работы (kill <pid>)
my $sigterm = EV::signal 'TERM', sub {
  &tracker_shutdown('SIGTERM');
};

# Загрузка торрентов
{
  my $start_time = EV::time;
  my $sql = '
      SELECT
          info_hash,
          poster_id,
          topic_id,
          complete_count,
          speed_down,
          speed_up,
          reg_time,
          seeder_last_seen,
          last_dl_time
      FROM
          bb_bt_torrents';
  my $result = &sql_query($sql);

  while( my($info_hash, $poster_id, $topic_id, $complete_count, $speed_down, $speed_up, $reg_time, $seeder_last_seen, $last_dl_time) = $result->fetchrow_array ) {
    $g_files{$info_hash} = {
      'complete_count'   => int($complete_count),
      'dirty'            => 0,
      'last_dl_time'     => int($last_dl_time),
      'leechers'         => 0,
      'peers'            => {},
      'poster_id'        => int($poster_id),
      'reg_time'         => int($reg_time),
      'seeder_last_seen' => int($seeder_last_seen),
      'seeders'          => 0,
      'speed_down'       => 0,
      'speed_up'         => 0,
      'topic_id'         => int($topic_id)
    };
    
    $g_topics{$topic_id} = $info_hash;
  }
  
  &print_event('CORE', sprintf('Торрент-файлы загружены (%s) за %.4f с', &num_format(scalar keys %g_files), EV::time - $start_time));
}

# Загрузка пользователей
# TODO: limit
{
  my $start_time = EV::time;
  my $sql = '
      SELECT
          user_id,
          auth_key,
          user_agent,
          can_leech
      FROM
          bb_bt_users';
  my $result = &sql_query($sql);

  while( my($user_id, $auth_key, $user_agent, $can_leech) = $result->fetchrow_array ) {
    $g_users{$auth_key} = {
      'bonus'      => 0,
      'can_leech'  => int($can_leech),
      'dirty'      => 0,
      'downloaded' => 0,
      'leeching'   => 0,
      'limit'      => $g_max_leeching,
      'released'   => 0,
      'seeding'    => 0,
      'speed_down' => 0,
      'speed_up'   => 0,
      'timebonus'  => 0,
      'uploaded'   => 0,
      'user_agent' => $user_agent,
      'user_id'    => int($user_id)
    };
  
    $g_uids{$user_id} = $auth_key;
  }

  &print_event('CORE', sprintf('Загружены данные пользователей (%s) за %.4f с', &num_format(scalar keys %g_users), EV::time - $start_time));
}

# Загрузка пиров
{
  my $start_time = EV::time;
  my $sql = '
      SELECT
          peer_hash,
          topic_id,
          user_id,
          ip,
          port,
          seeder,
          uploaded,
          downloaded,
          speed_up,
          speed_down,
          seeding,
          connect_time,
          update_time
      FROM
          bb_bt_tracker';
  my $result = &sql_query($sql);

  while( my($peer_hash, $topic_id, $user_id, $ip, $port, $seeder, $uploaded, $downloaded, $speed_up, $speed_down, $seeding, $connect_time, $update_time) = $result->fetchrow_array ) {
    $g_peers{$peer_hash} = {
      'downloaded' => int($downloaded),
      'mtime'      => int($update_time),
      'seeder'     => int($seeder),
      'seeding'    => int($seeding),
      'speed_down' => int($speed_down),
      'speed_up'   => int($speed_up),
      'stime'      => int($connect_time),
      'uploaded'   => int($uploaded),
      'user_id'    => int($user_id)
    };
    
    # Наполняем раздачи пирами из БД
    if( defined $g_topics{$topic_id} ) {
      my $auth_key  = $g_uids{$user_id};
      my $info_hash = $g_topics{$topic_id};

      if( defined $g_files{$info_hash} ) {
        $g_files{$info_hash}{'peers'}{$peer_hash} = pack('Nn', &ip2long($ip), int($port));

        if( int($seeder) ) {
          $g_files{$info_hash}{'seeders'}++;
          $g_users{$auth_key}{'seeding'}++;
        } else {
          $g_files{$info_hash}{'leechers'}++;
          $g_users{$auth_key}{'leeching'}++;
        }

        $g_files{$info_hash}{'dirty'} = 1;
        $g_users{$auth_key}{'dirty'} = 1;
        $g_files{$info_hash}{'speed_down'} += $speed_down;
        $g_files{$info_hash}{'speed_up'} += $speed_up;
      }
    }
  }
  
  &print_event('CORE', sprintf('Загружены данные пиров (%s) за %.4f с', &num_format(scalar keys %g_peers), EV::time - $start_time));
}

undef %g_topics;
undef %g_uids;

# Подключение к memcached
my $memcache = new Cache::Memcached::Fast({
  'servers' => [{
    'address' => '/var/run/memcached/memcached.lock',
    'noreply' => 1
  }]
});

# Настройки кэша
$g_cache_expire = $g_announce_interval + 60;
$g_cache_prefix = sprintf('ivacuum.ru_btt_%d_', $s_port);

&print_event('CORE', 'Подключение к memcached установлено');

# Занесение начального состояния ретрекера в memcache
$memcache->set($g_cache_prefix . 'status', encode_json({
  'accepted'  => 0,
  'completed' => 0,
  'files'     => 0,
  'rejected'  => 0,
  'peers'     => 0,
  'uptime'    => 0
}), $g_cache_expire);

# Создание сокета
my $fh = IO::Socket::INET->new(
  'Proto'     => 'tcp',
  'LocalAddr' => $s_ip,
  'LocalPort' => $s_port,
  'Listen'    => 50000,
  'ReuseAddr' => SO_REUSEADDR,
  'Blocking'  => 0
) or die("\nНевозможно создать сокет: $!\n");
setsockopt $fh, IPPROTO_TCP, TCP_NODELAY, 1;
setsockopt $fh, SOL_SOCKET, SO_LINGER, pack('II', 1, 0);
&print_event('CORE', 'Принимаем входящие пакеты по адресу ' . $s_ip . ':' . $s_port);

&print_event('RAM', 'files: ' . &num_format(total_size(\%g_files)));
&print_event('RAM', 'peers: ' . &num_format(total_size(\%g_peers)));
&print_event('RAM', 'users: ' . &num_format(total_size(\%g_users)));

# Принимаем подключения
my $event = EV::io $fh, EV::READ, sub {
  my $session = $fh->accept() or return 0;

  # Клиент закрыл соединение
  return &close_connection($session) if !$session->peerhost;

  # Неблокирующий режим работы
  $session->blocking(0);
  binmode($session);
  
  # &print_event('RECV', 'Подключился клиент ' . $session->peerhost . ':' . $session->peerport);

  # Функция обратного вызова для обработки
  # поступивших от клиента данных
  my $callback; $callback = sub {
    my $type = $_[0];

    # Таймаут
    if( $type & EV::TIMEOUT ) {
      # &print_event('CORE', 'Connection timeout');
      $g_rejected++;
      return &close_connection($session);
    }

    # Ошибка
    if( $type & EV::ERROR ) {
      &print_event('CORE', 'Connection error');
      $g_rejected++;
      return &close_connection($session);
    }

    # Чтение данных
    # local $/;
    # my $s_output = <$session>;
    my $s_output = '';
    sysread $session, $s_output, 1024;

    # Возможно излишняя проверка
    if( !defined $s_output ) {
      &print_event('CORE', '$s_output is not defined');
      return &close_connection($session);
    }

    $g_accepted++;
    &print_event('CORE', 'Подключений: ' . $g_accepted) if $g_accepted % 10000 == 0;

    $ev_unixtime = int(EV::now);

    if( $s_output =~ /^GET \/ann\?(.+) HTTP/ ) {
      # Запрос к анонсеру
      my %hash = &parse_qs($1);

      $hash{'info_hash'} =~ s|\%([a-f0-9]{2})|pack('C', hex($1))|ieg;
      $hash{'peer_id'} =~ s|\%([a-f0-9]{2})|pack('C', hex($1))|ieg;

      # Поступившие данные
      my $auth_key = $hash{'uk'} || '';
      my $compact = $hash{'compact'} || 1;
      my $corrupt = $hash{'corrupt'} || 0;
      my $downloaded = $hash{'downloaded'};
      my $event = $hash{'event'} || '';
      my $info_hash = $hash{'info_hash'};
      my $left = $hash{'left'};
      my $new_peer = 0;
      my $numwant = $hash{'numwant'} || 0;
      my $peer_id = $hash{'peer_id'};
      my $port = $hash{'port'} || 0;
      my $seeder = $left == 0 ? 1 : 0;
      my $uploaded = $hash{'uploaded'};
      my $user_agent;

      if( $s_output =~ /User-Agent: ([\da-zA-z\.\(\)\/]+)/ ) {
        # Торрент-клиент
        $user_agent = $1;
      } else {
        # Если клиент не передал свое название,
        # то берем сокращенное из peer_id
        $user_agent = substr $peer_id, 1, 6;
      }

      # &print_event('RECV', 'Подключился ' . $session->peerhost . ':' . $port . ' ' . $user_agent);

      # Проверка поступивших данных
      return &btt_msg_die($session, 'Трекер доступен только для абонентов Билайн-Калуга') if substr($session->peerhost, 0, 3) ne '10.';
      return &btt_msg_die($session, 'Ключ не найден - авторизуйтесь и скачайте торрент-файл заново') if !$auth_key or length($auth_key) != $g_auth_key_length;
      return &btt_msg_die($session, 'Неверный info_hash торрента') if !$info_hash or length($info_hash) != 20;
      return &btt_msg_die($session, 'Неверный peer_id клиента') if !$peer_id or length($peer_id) != 20;
      return &btt_msg_die($session, 'Неверный порт') if $port <= 0 or $port > 65535;
      return &btt_msg_die($session, 'Неверное значение downloaded') if $downloaded < 0;
      return &btt_msg_die($session, 'Неверное значение uploaded') if $uploaded < 0;
      return &btt_msg_die($session, 'Неверное значение left') if $left < 0;
      return &btt_msg_die($session, 'Неверный ключ авторизации') if !($auth_key =~ /^[a-zA-Z\d]{$g_auth_key_length}$/);
      return &btt_msg_die($session, 'Ваш клиент не поддерживает упакованные ответы') if $compact != 1;
      return &btt_msg_die($session, 'Торрент не зарегистрирован') if !defined $g_files{$info_hash} or !defined $g_files{$info_hash}{'poster_id'};
      return &btt_msg_die($session, 'Пользователь не найден - авторизуйтесь и скачайте торрент-файл заново') if !defined $g_users{$auth_key};
      
      if( $g_users{$auth_key}{'can_leech'} == 0 ) {
        # Пользователю запрещено скачивать чужие релизы. Можно только раздавать свои
        if( $g_users{$auth_key}{'user_id'} != $g_files{$info_hash}{'poster_id'} ) {
          return &btt_msg_die($session, 'Вы не можете качать торренты');
        }
      } elsif( $g_users{$auth_key}{'can_leech'} == 2 ) {
        # Пользователю запрещено скачивать новинки. Свои раздачи ограничение не затрагивает
        if( $g_users{$auth_key}{'user_id'} != $g_files{$info_hash}{'poster_id'} and $ev_unixtime - $g_files{$info_hash}{'reg_time'} < $g_snatch_delay ) {
          return &btt_msg_die($session, 'Вы не можете качать этот торрент ещё ' . int(($g_snatch_delay - ($ev_unixtime - $g_files{$info_hash}{'reg_time'})) / 86400) . ' дн.');
        }
      }

      # Отклонение частых запросов
      # if( !$event and defined $g_peers{$peer_hash} ) {
      #   if( $g_peers{$peer_hash}{'mtime'} + $g_announce_interval > $ev_unixtime + 60 ) {
      #     return &btt_msg($session, {
      #       'complete'   => $g_files{$info_hash}{'seeders'},
      #       'incomplete' => $g_files{$info_hash}{'leechers'},
      #       'downloaded' => $g_files{$info_hash}{'complete_count'},
      #       'interval'   => $g_peers{$peer_hash}{'mtime'} + $g_announce_interval - $ev_unixtime,
      #       'peers'      => ''
      #     });
      #   }
      # }

      # Уникальный ID пира
      # Изначально содержит 40 символов. 32 - чтобы влезло в поле кода md5
      $peer_hash = substr(sha1_hex($info_hash . $hash{'uk'} . $session->peerhost . $port), 0, 32);

      # &print_event('RECV', 'Клиент остановил торрент') if($event eq 'stopped');
      # &print_event('RECV', 'Клиент запустил торрент') if($event eq 'started');
      # &print_event('RECV', 'Клиент полностью скачал торрент') if($event eq 'completed');

      # Первое появление пира на раздаче
      if( !defined $g_files{$info_hash}{'peers'}{$peer_hash} ) {
        if( $left > 0 or $event eq 'completed' ) {
          # Подключился новый лич
          $g_files{$info_hash}{'leechers'}++;
          $g_users{$auth_key}{'leeching'}++;
        } else {
          # Подключился новый сид
          $g_files{$info_hash}{'seeders'}++;
          $g_users{$auth_key}{'seeding'}++;
        }

        $g_files{$info_hash}{'dirty'} = 1;
        $g_files{$info_hash}{'peers'}{$peer_hash} = pack('Nn', &ip2long($session->peerhost), $port);
        $g_users{$auth_key}{'dirty'} = 1;
        $new_peer = 1;
      }

      $g_files{$info_hash}{'mtime'} = $ev_unixtime;

      my($down_add, $speed_down, $speed_down_prev, $speed_up, $speed_up_prev, $up_add) = (0, 0, 0, 0, 0, 0);

      # Состояние закачек:
      # -1 = релизер
      #  0 = качает
      #  1 = скачал
      my $dlstatus = $left ? 0 : 1;
      my $releaser = $g_users{$auth_key}{'user_id'} == $g_files{$info_hash}{'poster_id'} ? 1 : 0;
      $dlstatus = -1 if $releaser;

      $g_dlstatus_buffer = sprintf('%s%s(%d, %d, %d)', $g_dlstatus_buffer, (($g_dlstatus_buffer) ? ', ' : ''), $g_files{$info_hash}{'topic_id'}, $g_users{$auth_key}{'user_id'}, $dlstatus);

      if( $new_peer or $event eq 'started' or $uploaded < $g_peers{$peer_hash}{'uploaded'} or $downloaded < $g_peers{$peer_hash}{'downloaded'} ) {
        # Новый пир
        $g_peers{$peer_hash} = {
          'downloaded' => $downloaded,
          'mtime'      => $ev_unixtime,
          'seeder'     => $seeder,
          'seeding'    => 0,
          'speed_down' => $speed_down,
          'speed_up'   => $speed_up,
          'stime'      => $ev_unixtime,
          'uploaded'   => $uploaded,
          'user_id'    => $g_users{$auth_key}{'user_id'}
        };
      } else {
        # Сколько скачал между анонсами
        if( $downloaded > $g_peers{$peer_hash}{'downloaded'} ) {
          $down_add = $downloaded - $g_peers{$peer_hash}{'downloaded'};
          $g_peers{$peer_hash}{'downloaded'} = $downloaded;
        }

        # Сколько раздал между анонсами
        if( $uploaded > $g_peers{$peer_hash}{'uploaded'} ) {
          $up_add = $uploaded - $g_peers{$peer_hash}{'uploaded'} - $corrupt;
          $g_peers{$peer_hash}{'uploaded'} = $uploaded;
        }

        # Определение скорости
        if( $ev_unixtime > $g_peers{$peer_hash}{'mtime'} ) {
          $speed_down = int($down_add / ($ev_unixtime - $g_peers{$peer_hash}{'mtime'}));
          $speed_up   = int($up_add / ($ev_unixtime - $g_peers{$peer_hash}{'mtime'}));
        }

        if( $speed_up > 13582912 ) {
          &db_ping();

          # Фиксирование превышения скорости
          my $sql = 'INSERT INTO bb_speed_exceed (note_id, user_id, topic_id, time, speed_up, uploaded, downloaded, user_agent) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)';
          my $result = $db->prepare($sql);
          $result->execute($g_users{$auth_key}{'user_id'}, $g_files{$info_hash}{'topic_id'}, $ev_unixtime, $speed_up, $uploaded, $downloaded, $user_agent);

          if( $speed_up > 100000000 ) {
            $g_users{$auth_key}{'can_leech'} = 0;
            return &btt_msg_die($session, 'Вы не можете качать торренты');
          }
        }

        # Время сидирования (для зачисления таймбонусов)
        $g_peers{$peer_hash}{'seeding'} += $ev_unixtime - $g_peers{$peer_hash}{'mtime'} if $seeder;

        $speed_down_prev = $g_peers{$peer_hash}{'speed_down'};
        $speed_up_prev   = $g_peers{$peer_hash}{'speed_up'};

        $g_peers{$peer_hash}{'mtime'} = $ev_unixtime;
        $g_peers{$peer_hash}{'speed_down'} = $speed_down;
        $g_peers{$peer_hash}{'speed_up'} = $speed_up;
      }

      if( $event eq 'stopped' ) {
        $speed_down = $speed_up = 0;
      }

      # Учет скачанного и отданного
      if( $down_add or $up_add ) {
        $g_users{$auth_key}{'bonus'} += $up_add if $seeder and !$releaser and $g_files{$info_hash}{'seeders'} == 1 and $g_peers{$peer_hash}{'seeder'} == 1;
        $g_users{$auth_key}{'dirty'} = 1;
        $g_users{$auth_key}{'downloaded'} += $down_add;
        $g_users{$auth_key}{'released'} += $up_add if $releaser;
        $g_users{$auth_key}{'uploaded'} += $up_add;
      }

      # Таймбонусы
      my $timebonus = int($g_peers{$peer_hash}{'seeding'} / $g_timebonus_interval);

      if( $timebonus > 0 ) {
        $g_peers{$peer_hash}{'seeding'} -= $timebonus * $g_timebonus_interval;
        $g_users{$auth_key}{'timebonus'} += $timebonus;
      }

      # Обновление данных торрент-файла
      $g_files{$info_hash}{'dirty'} = 1;
      $g_files{$info_hash}{'seeder_last_seen'} = $ev_unixtime if($seeder);
      $g_files{$info_hash}{'speed_down'} += $speed_down - $speed_down_prev;
      $g_files{$info_hash}{'speed_up'} += $speed_up - $speed_up_prev;

      # Для подсчета максимальных скоростей (+= не нужно)
      $g_users{$auth_key}{'speed_down'} = $speed_down - $speed_down_prev;
      $g_users{$auth_key}{'speed_up'} = $speed_up - $speed_up_prev;

      # Используемый клиент
      $g_users{$auth_key}{'user_agent'} = $user_agent;

      $numwant = $g_max_numwant if $numwant > $g_max_numwant;
      $numwant = $g_min_numwant if $numwant < $g_min_numwant;

      if( $event eq 'stopped' ) {
        # Удаление пира
        &delete_peer($info_hash, $peer_hash, $auth_key);
        
        # uTorrent 2.0.4+ требует список пиров даже при остановке торрента
        # Отдаем ему самого себя
        return &btt_msg($session, {
          'complete'   => $g_files{$info_hash}{'seeders'},
          'incomplete' => $g_files{$info_hash}{'leechers'},
          'downloaded' => $g_files{$info_hash}{'complete_count'},
          'interval'   => $g_announce_interval,
          'peers'      => pack('Nn', &ip2long($session->peerhost), $port)
        });
      } elsif( $event eq 'completed' and !$left and !$g_peers{$peer_hash}{'seeder'} ) {
        # Клиент завершил закачку торрента - стал сидом
        $g_files{$info_hash}{'complete_count'}++;
        $g_files{$info_hash}{'dirty'} = 1;
        $g_files{$info_hash}{'last_dl_time'} = $ev_unixtime;
        $g_files{$info_hash}{'leechers'}--;
        $g_files{$info_hash}{'seeders'}++;
        $g_peers{$peer_hash}{'seeder'} = 1;
        $g_users{$auth_key}{'dirty'} = 1;
        $g_users{$auth_key}{'leeching'}--;
        $g_users{$auth_key}{'seeding'}++;

        $g_complete_count++;
      }

      # Буфер для сброса в БД
      $g_peers_buffer = sprintf('%s%s("%s", %d, %d, "%s", %d, %d, %d, %d, %d, %d, %d, %d, "%s", %d, %d, %d)', $g_peers_buffer, (($g_peers_buffer) ? ', ' : ''), $peer_hash, $g_files{$info_hash}{'topic_id'}, $g_users{$auth_key}{'user_id'}, $session->peerhost, $port, $seeder, $releaser, $uploaded, $downloaded, $left, $speed_up, $speed_down, $user_agent, $g_peers{$peer_hash}{'seeding'}, $g_peers{$peer_hash}{'stime'}, $ev_unixtime);

      my($peers, $peers_count) = ('', 0);

      # Создание списка пиров для клиента
      foreach my $key (keys %{$g_files{$info_hash}{'peers'}}) {
        next if $key eq $peer_hash;
        next if $seeder and $g_peers{$key}{'seeder'} and $key ne $peer_hash;
        $peers .= $g_files{$info_hash}{'peers'}{$key};
        last if ++$peers_count == $numwant;
      }

      # Увеличиваем время анонса пропорционально количеству раздач в клиенте
      my $requests = int(($g_users{$auth_key}{'seeding'} + $g_users{$auth_key}{'leeching'}) * 1.25);
      
      # Чтобы обладатели большого количества раздач не были
      # раньше времени удалены как отключившиеся пиры
      $g_expiration_time = $requests + 60 if $requests + 60 > $g_expiration_time;

      # Анонс
      return &btt_msg($session, {
        'complete'   => $g_files{$info_hash}{'seeders'},
        'incomplete' => $g_files{$info_hash}{'leechers'},
        'downloaded' => $g_files{$info_hash}{'complete_count'},
        'interval'   => $requests > $g_announce_interval ? $requests : $g_announce_interval,
        'peers'      => $peers
      });
    } elsif( $g_debug > 1 and $s_output =~ /^GET \/dumper HTTP/ ) {
        # Дамп данных
        return &html_msg($session, 'Дамп данных', '<h3>g_files [' . (scalar keys %g_files) . ']</h3><pre>' . to_json(\%g_files, { pretty => 1 }) . '</pre><h3>g_peers [' . (scalar keys %g_peers) . ']</h3><pre>' . to_json(\%g_peers, { pretty => 1 }) . '</pre><h3>g_users [' . (scalar keys %g_users) . ']</h3><pre>' . to_json(\%g_users, { pretty => 1 }) . '</pre>');
    } elsif( $s_output =~ /^GET \/stats HTTP/ ) {
      # Запрос статистики
      return &html_msg($session, 'Статистика трекера', sprintf('<h3>Статистика трекера</h3><p>Трекер работает %s, обслуживает %s пиров на %s раздачах.</p><p>Подключений обслужено: %s. Отклонено по таймауту (%d сек): %.5f%% (%s).</p><p>Скачано торрентов через трекер: %s.</p>', &date_format($ev_unixtime - $g_starttime), &num_format(scalar keys %g_peers), &num_format(scalar keys %g_files), &num_format($g_accepted), $g_accept_interval, $g_rejected / ($g_accepted - $g_rejected), &num_format($g_rejected), &num_format($g_complete_count)));
    } elsif( $s_output =~ /^GET \/ping HTTP/ or $s_output =~ /^GET \%2Fping HTTP/ ) {
      # Проверка отклика
      return &html_msg_simple($session, "I'm alive! Don't worry.");
    } elsif( $s_output ) {
      # &print_event('CORE', 'Request: ' . $s_output);
      return &html_msg_simple($session, 'Неизвестный запрос');
    }
  };

  EV::once $session, EV::READ, $g_accept_interval, $callback;
};

##
## CRON
##
my $cron_exec = 1;

my $cron = EV::timer $g_cron_interval, $g_cron_interval, sub {
  return if $0 =~ /_dev/;

  $ev_unixtime = int(EV::now);

  #
  # Запись информации о состоянии закачек
  # Интервал: 1 минута (4 * $g_cron_interval)
  #
  &cron_dlstatus_write() if $cron_exec % 4 == 0;

  # Удаленные торрент-файлы
  &cron_torrents_deleted();

  # Дозагрузка новых торрентов
  &cron_files_read();

  #
  # Запись информации о торрент-файлах в БД
  # Интервал: 1 минута (4 * $g_cron_interval)
  #
  &cron_files_write() if $cron_exec % 4 == 0;

  #
  # Чтение информации о новых пользователях из БД
  # Интервал: 30 секунд (2 * $g_cron_interval)
  #
  &cron_users_read() if $cron_exec % 2 == 0;

  #
  # Запись информации о пользователях в БД
  # Интервал: 1 минута
  #
  &cron_users_write() if $cron_exec % 4 == 0;

  #
  # Удаление информации об отключившихся пирах
  # Интервал: 5 минут
  #
  &cron_peers_purge() if $cron_exec % 20 == 0;

  #
  # Запись состояния ретрекера в memcache
  # Интервал: 5 минут
  #
  if( $cron_exec % 20 == 0 ) {
    $memcache->replace($g_cache_prefix . 'status', encode_json({
      'accepted'  => $g_accepted,
      'completed' => $g_complete_count,
      'files'     => scalar keys %g_files,
      'rejected'  => $g_rejected,
      'peers'     => scalar keys %g_peers,
      'uptime'    => $ev_unixtime - $g_starttime
    }), $g_cache_expire);
  }
  
  #
  # Синхронизация количества сидов и личей на раздачах и
  # и количества раздаваемых и скачиваемых торрентов пользователями
  # Интервал: 3 часа
  #
  &cron_peers_sync() if $cron_exec % 720 == 0;

  $cron_exec = 0 if $cron_exec % 720 == 0;
  $cron_exec++;
};

EV::run;