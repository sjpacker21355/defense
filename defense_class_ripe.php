<?php
/**
 * @file
 * Contains Drupal\defense\ApiRipe.
 */
/*
 * Name:  defense_class_ripe.php               V1.0   2/16/20
 */
namespace Drupal\defense;

class ApiRipe{

  public function getApiStuff($inetnum) {
    //$apiKey = $countyAuthenticationObj->apiKey;
    //$apiURL = $countyAuthenticationObj->URL;
    //$user = $countyAuthenticationObj->User;
    //$url = 'https://rest-test.db.ripe.net/ripe/mntner/RIPE-DBM-MNT';
    //$url = 'http://rest.db.ripe.net/ripe/mntner/RIPE-DBM-MNT';
    //$url = 'http://rest.db.ripe.net/ripe/inetnum/193.0.0.0%20-%20193.0.7.255.json';
    
    //$url = 'http://rest.db.ripe.net/ripe/inetnum/103.208.220.226.json';
    //$url = 'http://rest.db.ripe.net/ripe/inet6num/95.211.230.211.json';
    
    $url = 'http://rest.db.ripe.net/ripe/inetnum/'.$inetnum.'.json';
    
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_HEADER, "Content-type: application/json");
    //curl_setopt($ch, CURLOPT_USERPWD, $user.':'.$apiKey.'|'.$database);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    defense_debug_msg('result',$result);
    if($result === FALSE) {
      defense_debug_msg('curl error', curl_error($ch));
      return FALSE;
    }
    curl_close($ch);
    $responseObj = json_decode($result);
    defense_debug_msg('responseobj',$responseObj);
    return $responseObj;
  }

            
}


