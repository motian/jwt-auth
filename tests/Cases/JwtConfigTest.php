<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf.
 *
 * @link     https://www.hyperf.io
 * @document https://doc.hyperf.io
 * @contact  group@hyperf.io
 * @license  https://github.com/hyperf-cloud/hyperf/blob/master/LICENSE
 */

namespace HyperfTest\Cases;

use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\Container;
use Hyperf\Utils\ApplicationContext;
use Mockery;
use Phper666\JwtAuth\Blacklist;
use Phper666\JwtAuth\Jwt;

/**
 * @internal
 * @coversNothing
 */
class JwtConfigTest extends AbstractTestCase
{
    public function testJwt()
    {
        /** @var Jwt $jwt*/
        $jwt = $this->getContainer()->get(Jwt::class);
        $this->assertNull($jwt->getPrefix());
        $jwt->setPrefix('prefix');

        $this->assertEquals('prefix', $jwt->getPrefix());
        $this->assertEquals('prefix', $jwt->getBlacklist()->getPrefix());
    }

    protected function getContainer()
    {
        $container = Mockery::mock(Container::class);
        $config = Mockery::mock(ConfigInterface::class);
        $config->shouldReceive('get')->andReturnNull();
        ApplicationContext::setContainer($container);

        $blacklist = new Blacklist();
        $container->shouldReceive('get')->with(Jwt::class)->andReturn(new Jwt($blacklist));
        $container->shouldReceive('get')->with(ConfigInterface::class)->andReturn($config);

        return $container;
    }
}
