<?php
/**
 * @file
 * Contains Drupal\defense\ApiArin.
 */
/*
 * Name:  defense_class_ripe.php               V1.0   2/16/20
 */
namespace Drupal\defense;

class ApiArin{

  public function getApiStuff($inetnum) {
    $url = 'http://whois.arin.net/rest/ip/'.$inetnum.'.json';
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_HEADER, "Content-type: application/json");
    //curl_setopt($ch, CURLOPT_USERPWD, $user.':'.$apiKey.'|'.$database);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    //defense_debug_msg('result',$result);
    if($result === FALSE) {
      defense_debug_msg('curl error', curl_error($ch));
      defense_debug_msg('result',$result);
      return FALSE;
    }
    curl_close($ch);
    $responseObj = json_decode($result);
    
    if(empty($responseObj->net)) {
      defense_debug_msg('responseobj',$responseObj);
      return NULL;
    }
    
    $netObj = $responseObj->net;
    if(!empty($netObj->orgRef)) {
      $orgRefObj = $netObj->orgRef;
      //defense_debug_msg('$orgRefObj',$orgRefObj);
      $handlerAttribute = '@handle';
      $ipHandler = $orgRefObj->$handlerAttribute;
    } elseif (!empty($netObj->customerRef)) { 
      $customerRefObj = $netObj->customerRef;
      //defense_debug_msg('$orgRefObj',$orgRefObj);
      $handlerAttribute = '@name';
      $ipHandler = $customerRefObj->$handlerAttribute;
    } else {
      $ipHandler = 'unknown';
    }
    
    $ipLookup['handler'] = $ipHandler;
    
    $dollarAttribute = '$';
    
    if(is_object($netObj->netBlocks->netBlock)) {
      $startAddress = $netObj->netBlocks->netBlock->startAddress->$dollarAttribute;
      //$startAddress = $startAddressObj->$dollarAttribute;
      $ipLookup['addresses'][0]['startAddress'] = $startAddress;
      $endAddress = $netObj->netBlocks->netBlock->endAddress->$dollarAttribute;
      //$startAddress = $startAddressObj->$dollarAttribute;
      $ipLookup['addresses'][0]['endAddress'] = $endAddress;
    } else {
      foreach ($netObj->netBlocks->netBlock as $key => $netBlockObj) {
        $startAddress = $netBlockObj->startAddress->$dollarAttribute;
        $ipLookup['addresses'][$key]['startAddress'] = $startAddress;
        $endAddress = $netBlockObj->endAddress->$dollarAttribute;
        $ipLookup['addresses'][$key]['endAddress'] = $endAddress;
      }
    }
    
    
    //defense_debug_msg('responseobj',$responseObj);
    return $ipLookup;
  }

            
}


