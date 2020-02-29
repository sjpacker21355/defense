<?php
/**
 * @file
 * Contains Drupal\defense\defense.
 */
/*
 * Name: defense_class_hacklog.php   V1.0 2/15/20
 *
 */
namespace Drupal\defense;

class HackLog{
  
  const WATCHDOGBL = "watchdog";
  const KNOWNIPTBL = "ip_known";

 
  private $schema = 
    array(
      'ip_log' => array(
        'description' => 'record of IP addresses that attempt unauthorized access.',
        'fields' => array(
          'IPkey' => array( 'type'=>'int','unsigned'=>TRUE,'size'=>'big','not null' => TRUE,'description'=>'Field fieldname of tablename.',),
          'IPaddr' => array( 'type'=>'char', 'length'=>16,),
          'Hits' => array( 'type' => 'int', 'size'=>'normal',),
          'OrgID' => array( 'type'=>'varchar', 'length'=>16,),
        ),
        'primary key' => array( 'IPkey', ),
      )
  );
  
  private function ipLog($org) {
    $user = $GLOBALS['user'];  
    //global $items;
    //nlp_debug_msg('items', $_SERVER);
    $ip = $user->hostname;
    $organization = $org;
    $ipSubNets = $this->getIpAddrs();
    nlp_debug_msg('subnets', $ipSubNets);
    if(!empty($ipSubNets)) {
      foreach ($ipSubNets as $ipSubNet => $record) {
        $subNetBase = $this->cidr_match($ip, $ipSubNet);
        if(!empty($subNetBase)) {
          $organization = $record['orgId'];
          $cidr = $ipSubNet;
          break;
        }
      }
    }
    if(empty($subNetBase)) {
      $subNetBase = $ip;
      $cidr = $ip;
    }
    $ipInt = ip2long($subNetBase);
    //db_set_active(NLP_DATABASE);
    try {
      db_merge(self::IPLOGTBL)
        ->key(array(
          'IPkey' => $ipInt,
          ))
        ->fields(array(
          //'IPkey' => $ipInt,
          'IPaddr' => $cidr,
          'Hits' => 1,
          'OrgID' => $organization,
        ))
        ->expression('Hits', 'Hits + :inc', array(':inc' => 1))
        ->execute();
      //db_set_active('default');
    }
    catch (Exception $e) {
      //db_set_active('default');
      //nlp_debug_msg('e', $e->getMessage() );
      return FALSE;
    }
    //db_set_active('default');
  }
  
  public function ipLogError() {
    $this->ipLog('unknown');
  }
  
  public function ipLogUser($label) {
    $this->ipLog($label);
  }
  
  
  public function getIpLog() {
    $query = db_select(self::IPLOGTBL, 'g')
      ->fields('g');
    $result = $query->execute();
    //iplog_debug_msg('result', $result);
    $logs = array();
    do {
      $record = $result->fetchAssoc();
      //iplog_debug_msg('record', $record);
      if(empty($record)) {break;}
      $ipKey = $record['IPkey'];
      $logs[$ipKey]['ipAddr'] = $record['IPaddr'];
      $logs[$ipKey]['hits'] = $record['Hits'];
      $logs[$ipKey]['orgId'] = $record['OrgID'];
    } while (TRUE);   
    return $logs;
  }
  
  public function deleteIpLogEntry($ipKey) {
    db_delete(self::IPLOGTBL)
      ->condition('IPkey', $ipKey)
      ->execute();
  }
  
  public function getIpAddrs() {
    $query = db_select(self::KNOWNIPTBL, 'k')
      ->fields('k');
    $result = $query->execute();
    $knownIps = array();
    do {
      $record = $result->fetchAssoc();
      //iplog_debug_msg('record', $record);
      if(empty($record)) {break;}
      $cidr = $record['CIDR'];
      $knownIps[$cidr]['orgId'] = $record['OrgID'];
      $knownIps[$cidr]['type'] = $record['Type'];
    } while (TRUE);   
    return $knownIps;
  }
  
  public function setIpAddr($range,$name,$type) {
    db_merge(self::KNOWNIPTBL)
      ->key(array('CIDR'=> $range))
      ->fields(array(
        'OrgID' => $name,
        'Type' => $type,
      ))
      ->execute();
  }
  
  public function resetIpAddrs() {
    db_truncate(self::KNOWNIPTBL)
      ->execute();
  }
  
  public function cidr_match($ip, $range) {
    list ($subnetbase, $bits) = explode('/', $range);
    $ipInt = ip2long($ip);
    $subnet = ip2long($subnetbase);
    $mask = -1 << (32 - $bits);
    $subnet &= $mask; 
    if(($ipInt & $mask) == $subnet) {
      return $subnetbase;
    }
    return NULL;
  }
  
  public function cidrconv($net) { 
    $start = strtok($net,"/"); 
    $n = 3 - substr_count($net, "."); 
    if ($n > 0){
      for ($i = $n;$i > 0; $i--) {
        $start .= ".0";
      }
    } 
    $bits1 = str_pad(decbin(ip2long($start)), 32, "0", STR_PAD_LEFT);
    $net2 = (1 << (32 - substr(strstr($net, "/"), 1))) - 1; 
    $bits2 = str_pad(decbin($net2), 32, "0", STR_PAD_LEFT); 
    $final = "";
    for ($i = 0; $i < 32; $i++)
    { 
      if ($bits1[$i] == $bits2[$i]) {$final .= $bits1[$i]; }
      if ($bits1[$i] == 1 and $bits2[$i] == 0) {$final .= $bits1[$i]; }
      if ($bits1[$i] == 0 and $bits2[$i] == 1) {$final .= $bits2[$i]; }
    } 
    return array($start, long2ip(bindec($final))); 
  }

  public function cidr_conv($cidr_address) {
    $first = substr($cidr_address, 0, strpos($cidr_address, "/"));
    $netmask = substr(strstr($cidr_address, "/"), 1);
    if(empty($netmask)) {return array($first,NULL);}
    $first_bin = str_pad(decbin(ip2long($first)), 32, "0", STR_PAD_LEFT);
    $netmask_bin = str_pad(str_repeat("1", (integer)$netmask), 32, "0", STR_PAD_RIGHT);
    $last_bin = '';
    for ($i = 0; $i < 32; $i++) {
      if ($netmask_bin[$i] == "1") {
        $last_bin .= $first_bin[$i];
      } else {
        $last_bin .= "1";
      }
    }
    $last = long2ip(bindec($last_bin));
    return array($first, $last);
    //return "$first - $last";
  } 

  public function ip2cidr($ip_start,$ip_end) {
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
  
}
