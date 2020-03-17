<?php

namespace unit;

use InvalidArgumentException;
use Phore\App\Mod\OAuth\OAuthModule;
use Phore\FileSystem\Exception\FileNotFoundException;
use PHPUnit\Framework\TestCase;

class OAuthModuleTest extends TestCase
{
    public function testConstructWithClientSecretFromString()
    {
        $module = new OAuthModule("https://login.talpa-services.de?client_id=tadis&client_secret=testSecret&scopes[]=val1&scopes[]=val2");
    }

    public function testConstructWithClientSecretFromFile()
    {
        $module = new OAuthModule("https://login.talpa-services.de?client_id=tadis&scopes[]=val1&scopes[]=val2&client_secret_from_file=/opt/tests/data/secretfile.txt");
    }

    public function testExceptionConstructWithClientSecretFromNonExistingFile()
    {
        $this->expectException(FileNotFoundException::class);
        $this->expectExceptionMessage("File 'path/to/file' not found");
        $module = new OAuthModule("https://login.talpa-services.de?client_id=tadis&scopes[]=val1&scopes[]=val2&client_secret_from_file=path/to/file");
    }

    public function testExceptionConstructWithoutClientID()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Param 'client_id' not defined in oauth2 URI");
        $module = new OAuthModule("https://login.talpa-services.de?scopes[]=val1&scopes[]=val2&client_secret_from_file=path/to/file");
    }

    public function testExceptionConstructWithSingleScope()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Param 'client_id' not defined in oauth2 URI");
        $module = new OAuthModule("https://login.talpa-services.de?scopes[]=val1&client_secret_from_file=path/to/file");
    }
}
