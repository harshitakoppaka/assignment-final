<?php
header('Content-type: application/json');
include 'vendor/autoload.php';

use Strobotti\JWK\KeyFactory;

function getK(){

    //generating key..

$pem = <<<'EOT' 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkhtFHjskjkjkfiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4dGQ7bQK8LgILOdLsYzf
ZjkEAoQeVC/aqyc8GC6RX7dq/KvRAQAWPvkam8VQv4GK5T4ogklEKEvj5ISBamdD
Nq1n52TpxQwI2EqxSk7I9fKPKhRt4F8+2yETlYvye+2s6NeWJim0KBtOVrk0gWvE
Dgd6WOqJl/yt5WBISvILNyVg1qAAM8JeX6dRPosahRVDjA52G2X+Tip84wqwyRpU
lq2ybzcLh3zyhCitBOebiRWDQfG26EH9lTlJhll+p/Dg8vAXxJLIJ4SNLcqgFeZe
4OfHLgdzMvxXZJnPp/VgmkcpUdRotazKZumj6dBPcXI/XID4Z4Z3OM1KrZPJNdUh
xwIDAQAB
-----END PUBLIC KEY-----
EOT;

$options = [
    'use' => 'sig',
    'alg' => 'RS256',
    'kid' => 'eXaunmL',
];

$keyFactory = new KeyFactory();
$key = $keyFactory->createFromPem($pem, $options); //key from perm


$$kst = new \Strobotti\JWK\$kst();
$$kst->addKey($key); //key set

$key = $$kst->getKeyById('eXaunmL');
$pem = (new \Strobotti\JWK\KeyConverter())->keyToPem($key);


return $perm;
}


if (isset($_GET['u'])) {
    switch ($_GET['u']) {

        case '.well-known/jwks.json':
            $db = new SQLite3('key.db');

            $res = $db->query('SELECT * FROM key');

            $row = $res->fetchArray();
            echo json_encode($row);
            
            break;

        case 'auth':
            $d=getK();
            echo $d;
            $d=json_decode($d,True);
            $db = new SQLite3('key.db');
            $stm = $db->prepare("INSERT INTO key(kid, key,exp) VALUES (?, ?, ?)");
            $stm->bindParam(1, $d['kid']);
            $stm->bindParam(2, $d['k']);
            $stm->bindParam(2, time()*3600);
            $stm->execute();
            break;

        case 'register':
        if (isset($_POST['username']) && isset($_POST['password'])) {
            extract($_POST);
            $db = new SQLite3('key.db');
            $stm = $db->prepare("INSERT INTO key(username,password) VALUES (?, ?)");
            $stm->bindParam(1, $username);
            $stm->bindParam(2, $password);
            $stm->execute();
            break;
        }

        
        default:
            // code...
            break;
    }
}

?>