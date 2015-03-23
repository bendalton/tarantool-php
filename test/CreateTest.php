<?php
class CreateTest extends PHPUnit_Framework_TestCase
{
    protected static $uri;
    protected static $uri_alt;

    public static function setUpBeforeClass() {
        self::$uri = sprintf('tcp://%s:%s', 'localhost', getenv('PRIMARY_PORT'));
        self::$uri_alt = sprintf('%s:%s', 'localhost', getenv('PRIMARY_PORT'));
    }


    public function test_00_create_basic()
    {
        $c = new Tarantool(self::$uri);
        $c->connect();
        $this->assertTrue($c->ping());
        $c->close();
    }
    public function test_00_create_alt_basic()
    {
        $c = new Tarantool(self::$uri_alt);
        $c->connect();
        $this->assertTrue($c->ping());
        $c->close();
    }
     public function test_01_create_test_ping_and_close()
    {
        $c = new Tarantool(self::$uri);
        $c->connect();
        $c->connect();
        $this->assertTrue($c->ping());
        $c->close();
        $this->assertTrue($c->ping());
        $c->close();
        $c->close();
    }

    /**
     * @expectedException Exception
     * @expectedExceptionMessage Failed to connect.
     */
    public function test_02_create_error_host() {
        (new Tarantool('very_bad_host'))->connect();
    }

    /**
     * @expectedException Exception
     * @expectedExceptionMessage Failed to connect.
     */
    public function test_03_create_error_port() {
        (new Tarantool('localhost:65500'))->connect();
    }

    public function test_04_create_many_conns()
    {
        $a = 1;
        while ($a < 20) {
            $this->assertTrue((new Tarantool('127.0.0.1', self::$port))->ping());
            $a++;
        }
    }
}
