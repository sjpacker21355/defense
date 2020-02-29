<?php
/**
 * @file
 * Contains Drupal\defense\WatchHack.
 */
/*
 * Name: defense_class_watchhack.php   V1.0 2/15/20
 *
 */
namespace Drupal\defense;

class WatchHack{
  
  const WATCHDOGTBL = "watchdog";
  const FAILED = "Login attempt failed";
 
  private $types = array(
    'user' => 'user',
    'page' => 'page not found',
    'nlp_user' => 'nlp_user',
  );
 
  
  public function getWatchHack($type) {
    $query = db_select(self::WATCHDOGTBL, 'r')
      ->fields('r');
    $result = $query->execute();
    $reports = array();
    do {
      $record = $result->fetchAssoc();
      //defense_debug_msg('record',$record);
      if(empty($record)) {break;}
      $wid = $record['wid'];
      $recordType = $record['type'];
      if($recordType == $this->types[$type]) {
        //$message = $record['message'];
        

        $reports[$wid]['type'] = $record['type'];
        $reports[$wid]['message'] = $record['message'];
        $reports[$wid]['hostname'] = $record['hostname'];
        $variables = unserialize($record['variables']);
        
        $reports[$wid]['user'] = NULL;
        if(!empty($variables['%user'])) {
          $reports[$wid]['user'] = $variables['%user'];
        }
        $reports[$wid]['variables'] = $variables;
          
        
      }
      
    } while (TRUE);   
    return $reports;
  }
  
 
  
}
