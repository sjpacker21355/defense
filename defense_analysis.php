<?php
/*
 * Name: defense_analysis.php   V1.0  2/15/20
 */

require_once "defense_class_hacklog.php";
require_once "defense_class_watchhack.php";
require_once "defense_class_ripe.php";
require_once "defense_class_arin.php";

use Drupal\defense\WatchHack;
use Drupal\defense\ApiRipe;
use Drupal\defense\ApiArin;

function ip2cidr($ip_start,$ip_end) {
    if(long2ip(ip2long($ip_start))!=$ip_start or long2ip(ip2long($ip_end))!=$ip_end) {return NULL;}
    $ipl_start=(int)ip2long($ip_start);
    $ipl_end=(int)ip2long($ip_end);
    if($ipl_start>0 && $ipl_end<0) {
      $delta=($ipl_end+4294967296)-$ipl_start;
    } else {
      $delta=$ipl_end-$ipl_start;
    }
    $netmask=str_pad(decbin($delta),32,"0",STR_PAD_LEFT);
    if(ip2long($ip_start)==0 && substr_count($netmask,"1")==32) {return "0.0.0.0/0";}
    if($delta<0 or ($delta>0 && $delta%2==0)) {return NULL;}
    for($mask=0;$mask<32;$mask++) {
      if($netmask[$mask]==1) {break;}
    }
    if(substr_count($netmask,"0")!=$mask) {return NULL;}
    return "$ip_start/$mask";
  } 

function defense_analysis() {
  
  $output = 'big test';
  
  $watchHackObj = new WatchHack();
  $reports = $watchHackObj->getWatchHack('user');
  //defense_debug_msg('userreports',$reports);
  
  //$ripeApiObj = new ApiRipe();
  $arinApiObj = new ApiArin();
  
  $knownIpRanges = array();
  
  
  $output .= '<br>Failed user login - possible hack.';
  foreach ($reports as $report) {
    $message = $report['message'];
    $failedPos = strpos($message, 'attempt failed');
    
    $credentialsPos = strpos($message, 'credentials:');
    if($credentialsPos !== FALSE) {
      
      
      $unknownPos = strpos($message, 'Unknown');
      if($unknownPos !== FALSE) {$failedPos = $unknownPos;}
    }
    
    
    if($failedPos === FALSE) {continue;}
    //defense_debug_msg('message, pos: '.$pos, $message);
    $hostname = $report['hostname'];
    
    $possibleHack = $arinApiObj->getApiStuff($hostname);
    //defense_debug_msg('possibleHack',$possibleHack);
    $msg = '<br>User: '.$report['user'].' handler: '.$possibleHack['handler'].' addresses: ';
    $first = TRUE;
    $ipRanges = '';
    foreach ($possibleHack['addresses'] as $address) {
      if(!$first) {
        $first = FALSE;
      } else {
        $ipRanges .= ' , ';
      }
      $ipRanges .= $address['startAddress'].'-'.$address['endAddress'];
    }
    if(empty($knownIpRanges[$ipRanges])) {
      $knownIpRanges[$ipRanges] = $ipRanges;
      $output .= $msg.$ipRanges;
    }
  }
  
  $output .= '<br><br>Page not found - possible hack.';
  
  $notFoundPages = $watchHackObj->getWatchHack('page');
 // defense_debug_msg('notfound',$notFoundPages);
  foreach ($notFoundPages as $notFoundPage) {
    $hostname = $notFoundPage['hostname'];
    
    $possibleHack = $arinApiObj->getApiStuff($hostname);
    //defense_debug_msg('possibleHack',$possibleHack);
    $first = TRUE;
    $msg = '<br>User: '.$notFoundPage['user'].' handler: '.$possibleHack['handler'].' addresses: ';
    $ipRanges = '';
    foreach ($possibleHack['addresses'] as $address) {
      if(!$first) {
        $first = FALSE;
      } else {
        $ipRanges .= ' , ';
      }
      $ipRanges .= $address['startAddress'].'-'.$address['endAddress'];
    }
    if(empty($knownIpRanges[$ipRanges])) {
      $knownIpRanges[$ipRanges] = $ipRanges;
      $output .= $msg.$ipRanges;
    }
    
  }
  
  $output .= '<br><br>NLP user login - not whitelisted.';
  
  $whielisRanges = array();
  $whitelist = iplog_get_ip_list('whitelist');
  $nlpUsers= $watchHackObj->getWatchHack('nlp_user');
 // defense_debug_msg('notfound',$notFoundPages);
  foreach ($nlpUsers as $nlpUser) {
    $hostname = $nlpUser['hostname'];
    
    $whitelisted = FALSE;
    foreach ($whitelist as $whitelistIp) {
      if (iplog_check_ip($whitelistIp->ip, $hostname)) {
        $whitelisted = TRUE;
        break;
      }
    }
    
    if(!$whitelisted) {
      $handler = $arinApiObj->getApiStuff($hostname);
      //defense_debug_msg('possibleHack',$possibleHack);
      $first = TRUE;
      $msg = '<br>User: '.$nlpUser['user'].' handler: '.$handler['handler'].' addresses: ';
      $ipRanges = '';
      foreach ($handler['addresses'] as $address) {
        if(!$first) {
          $first = FALSE;
        } else {
          $ipRanges .= ' , ';
        }
        $cidr = ip2cidr($address['startAddress'],$address['endAddress']);
        $ipRanges .= $address['startAddress'].'-'.$address['endAddress'].', '.$cidr;
      }
      if(empty($whielisRanges[$ipRanges])) {
        $whielisRanges[$ipRanges] = $ipRanges;
        $output .= $msg.$ipRanges;
      }
    }
    
      
    
  }

  
  
  return $output;
}
