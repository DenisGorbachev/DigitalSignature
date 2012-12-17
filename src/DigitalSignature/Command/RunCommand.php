<?php

namespace DigitalSignature\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

define('CRYPT_RSA_EXPONENT', '65537');

class RunCommand extends Command
{
    protected function configure()
    {
        $this
            ->setName('run')
            ->setDescription('Practice #5')
            ->addArgument('message', InputArgument::REQUIRED, 'Message to be encoded')
    ;}

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $message = $input->getArgument('message');

        $output->writeln(sprintf('Message : "%s"', $message));

        $cipher = new \Crypt_RSA();
        $cipher->setPrivateKeyFormat(CRYPT_RSA_PRIVATE_FORMAT_XML);
        $cipher->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_XML);
        $cipher->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
        $keystore = $cipher->createKey();
        $privatekey = $keystore['privatekey'];
        $publickey = $keystore['publickey'];
        $privatekeySimpleXml = new \SimpleXMLElement($privatekey);
        $publickeySimpleXml = new \SimpleXMLElement($publickey);

        $output->writeln(sprintf('RSA: e = "%s"', bin2hex(base64_decode($publickeySimpleXml->Exponent))));
        $output->writeln(sprintf('     n = "%s"', bin2hex(base64_decode($publickeySimpleXml->Modulus))));
        $output->writeln(sprintf('     d = "%s"', bin2hex(base64_decode($privatekeySimpleXml->D))));

        $md5Message = md5($message);

        $output->writeln(sprintf('HashCode(Message) = "%s"', $md5Message));

        $cipher->loadKey($privatekey);
        $signature = $cipher->sign($md5Message);

        $output->writeln(sprintf('Sign = "%s"', bin2hex($signature)));

        $cipher->loadKey($publickey);
        $verified = $cipher->verify($md5Message, $signature);
        $output->writeln('Receiver:');
        $output->writeln(sprintf('h = "%s"', $md5Message));
        $output->writeln(sprintf('h == HashCode(Message) : "%s"', $verified? 'true' : 'false'));
    }

}
