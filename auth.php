<?php

/**
 * Chained authentication backend.
 * Will check a list of auth backends in turn for the supplied user.
 *
 * Profile can be updated for any backend with "Profile" capability.
 * We detect profile by finding the auth for the current user
 * as specified by $_SERVER['REMOTE_USER']
 *
 * UserManager can only be used with one of the backends because
 * it assumes the backend capabilities are set at construction
 * but in this case they would be user specific.
 *
 * Configuration
 * $conf['authtype'] = 'chained'
 * $conf['plugin']['authchained']['authtypes'] = # : separated list of authtypes, eg 'ldap:plain'
 * $conf['plugin']['authchained']['usermanager_authtype'] = null; # which of the authtypes should be checked for usermanager capabilities
 * $conf['plugin']['authchained']['find_auth_by_password'] = false; # Follow the chain in the checkpass method.
 * $conf['plugin']['authchained']['debug'] = false; # debugging
 * $conf['plugin']['authchained']['debug_hidden'] = false; #hide debug in html output @see dbg() in infoutils
 * $conf['plugin']['authchained']['debug_to_file'] = false; #also debug to file @see dbglog in infoutils
 *
 * NOTE: The "plain" backend calls "cleanID" on the request attributes outside of the class
 * instance, thus ruining everything for other backends in the chain.
 * If you comment out that code this should be fine. Perhaps I should raise a case for that.
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Grant Gardner <grant@lastweekend.com.au>
 * @author  Modification for Weatherwax by Michael Braun <michael-dev@fami-braun.de> (C) 2013-03-08 
 * @version    0.5
 * @date    March 2013
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

//class auth_chained extends auth_simple {
class auth_plugin_authchained extends DokuWiki_Auth_Plugin {
    protected $debug = false;
    protected $debug_hidden = false;
    protected $debug_file = false;
    //Chain of other auths..
    protected $chain = array();
    //Backend to use with usermanager
    protected $user_manager_auth = null;
    //Traversing the chain is expensive. Cache some userinfo
    protected $user_cache = array();

    public function __construct() {
      parent::__construct();
        
      $this->find_auth_by_password = (boolean) $this->getConf('find_auth_by_password');
      
      // Create the auth chain... split string, create auths.
      $link_names = split("[:,;]", $this->getConf('authtypes'));
      $count = count($link_names);
 
      for ($i=0; $i<$count; $i++) {
        $link_name=$link_names[$i];
     
        $link_auth = $this->createAuth($link_name);
        if ($link_auth && $link_auth->success) {
          $this->chain[$link_name]=$link_auth;
            
          if ($link_name == $this->getConf('usermanager_authtype')) {
            $this->user_manager_auth = $link_auth;
          }
        } else {
          $this->show_error("Problem constructing $auth_class");
          $this->success = false;
        } 
      }

      $this->debug = (boolean) $this->getConf('debug');
      $this->debug_hidden = (boolean) $this->getConf('debug_hidden');
      $this->debug_file = (boolean) $this->getConf('debug_to_file');
    }
 
    protected function createAuth($auth_name)  {
      global $plugin_controller;
      $auth = null;
      foreach ($plugin_controller->getList('auth') as $plugin) {
        if ($auth_name === $plugin) {
          $auth = $plugin_controller->load('auth', $plugin);
          break;
        }
      }

      return $auth;
    }
    
    /**
    * OK so we're not supposed to override this
    * but because our capabilities are context specific
    * we'll create this dirty hack
    */
    public function canDo($cap) {
        switch($cap) {
          case 'Profile':
          case 'logout':
              //Depends on current user.
              $user_auth = $this->getAuthFromUser();
              if ($user_auth != false) {
                 return $user_auth->canDo($cap);
              }
              return false;
          case 'UserMod':
          case 'addUser':
          case 'delUser':
          case 'getUsers':
          case 'getUserCount':
          case 'getGroups':
              //Depends on the auth for use with user manager
              if ($this->user_manager_auth != false) {
                 return $this->user_manager_auth->canDo($cap);
              }
              return false;
          case 'modPass':
          case 'modName':
          case 'modLogin':
          case 'modGroups':
          case 'modMail':
              //Depends whether we are looking at the profile (Current user)
              //or User Manager
              $capability_auth = $this->getAuthFromRequest();
              if ($capability_auth != false) {
                 return $capability_auth->canDo($cap);
              }
          case 'external':
              //We are external if one of the chains is valid for external use 
              return $this->trustExternal($_REQUEST['u'],$_REQUEST['p'],$_REQUEST['r']);
        default:
             //Everything else (false)
              return parent::canDo($cap);
       }
    }
 
    public function trustExternal($user,$pass,$sticky=false){
        global $USERINFO;
   
        if (isset($USERINFO)
            && !empty($USERINFO['authtype'])
            && $this->chain[$USERINFO['authtype']]->canDo('external')) {
            //We've been here before...
            return true;
        }
        
        foreach ($this->chain as $link_name => $link_auth) {
      
           if ($link_auth->canDo('external') && $link_auth->trustExternal($user,$pass,$sticky)) {
                 $found_user = $_SERVER['REMOTE_USER'];
                 $this->log_debug("trustExternal found $found_user in $link_name");
                 $USERINFO['authtype'] = $link_name;
                 $this->user_cache[$found_user] = $USERINFO;
                 return true;
           }
                     
         }
         
         return false;
   
    }


    /**
    * Use request attributes to guess whether we are in the Profile or UserManager
    * and return the appropriate auth backend
    */
    protected function getAuthFromRequest() {
         global $ACT;
         if ($ACT == "admin" && $_REQUEST['page']=="usermanager") {
            return $this->user_manager_auth;
         } else {
            // assume we want profile info.
            return $this->getAuthFromUser();
         }
    }
 
    protected function getAuthFromUser($user = null) {
        global $USERINFO;
  
        if (empty($user) || $user == $_SERVER['REMOTE_USER']) {
           //Use current user. See if we already have the global $USERINFO, if not use REMOTE_USER
              if (isset($USERINFO) && !empty($USERINFO['authtype'])) {
                 $userinfo = $USERINFO;
              } else {
                 $userinfo = $this->getUserData($_SERVER['REMOTE_USER']);
              }
        } else {
           $userinfo = $this->getUserData($user);
        }
        if (!empty($userinfo) && isset($userinfo['authtype'])) {
            return $this->chain[$userinfo['authtype']];
        }
        return false;
    }
 
    /**
     * Return user info
     *
     * Delegate to the first link in the chain that has this user
     *
     * We also include which auth backend the user is associated with
     * so we can retrieve it later.
     *
     * and cache the result..
     */
     public function getUserData($user){
         if (empty($user)) {
             return false;
         }
    
         $cache_result = $this->user_cache[$user];
         if (!empty($cache_result)) {
           return $cache_result;
         }
    
         $userinfo = false;
         foreach ($this->chain as $link_name => $link_auth) {
             if ($link_auth->canDo('external')) {
               continue;
             }
             
             $userinfo = $link_auth->getUserData($user);
             if ($userinfo != false) {
                 $userinfo['authtype'] = $link_name;
                 break;
             }
         }
         $this->user_cache[$user] = $userinfo;
         $this->log_debug("getUserData() found %s in %s",$user,$userinfo['authtype']);
   
         return $userinfo;
    }
 
    function checkPass($user,$pass) {
    
      if ($this->find_auth_by_password) {
        foreach ($this->chain as $link_name => $link_auth) {
            //msg("Searching for $user in $link_name>",-1,__LINE__,__FILE__);
   
            if ($link_auth->canDo('external')) {
              continue;
            }
            
            if ($link_auth->checkPass($user,$pass)) {
              $this->log_debug("checkPass() found $user in $link_name");
              $userinfo = $link_auth->getUserData($user);
              $userinfo['authtype'] = $link_name;
              $this->user_cache[$user] = $userinfo;
              return true;
            }    
        }
      
        return false;
      }
    
      $user_auth = $this->getAuthFromUser($user);
    
      $passOK = false;
      if ($user_auth != false) {
        $passOK = $user_auth->checkPass($user,$pass);
      }
      //debug which authtype failed..
      return $passOK;
    }
 
  function modifyUser($user, $changes) {
    $user_auth = $this->getAuthFromUser($user);
    if ($user_auth != false) {
        if ($user_auth->modifyUser($user,$changes)) {
 
              //Update the cache entry with changes. Keep authtype.
              $auth_name = $this->user_cache[$user]['authtype'];
              $this->user_cache[$user] = $user_auth->getUserData($user);
              $this->user_cache[$user]['authtype'] = $auth_name;
 
              //msg("Updated $user mail=".$this->user_cache[$user]['mail']);
              return true;
        }
    }
    return false;
  }
 
  function createUser($user,$pass,$name,$mail,$grps=null){
     return $this->user_manager_auth->createUser($user,$pass,$name,$mail,$grps);
  }
 
  function deleteUsers($users) {
    //TODO. Remove users from cache. Probably not necessary on a per request basis.
    return $this->user_manager_auth->deleteUsers($users);
  }
 
  function getUserCount($filter=array()) {
    return $this->user_manager_auth->getUserCount($filter);
  }
 
  function retrieveUsers($start=0,$limit=-1,$filter=null) {
    return $this->user_manager_auth->retrieveUsers($start,$limit,$filter);
  }
 
  function addGroup($group) {
    return $this->user_manager_auth->addGroup($group);
  }
 
  function retrieveGroups($start=0,$limit=0) {
    return $this->user_manager_auth->retrieveGroups($start,$limit);
  }
 
  function useSessionCache($user){
    $user_auth = $this->getAuthFromUser($user);
    if (!empty($user_auth)) {
      return $user_auth->useSessionCache($user);
    }
    return false;
  }

  function logOff() {
    foreach ($this->chain as $link_name => $link_auth) {
      $link_auth->logOff();
    }
  }

  protected  function log_debug() {
      
      if ($this->debug) {
          $args = func_get_args();
          $msg = array_shift($args);
          
          if (count($args) > 0) {
              $msg = vsprintf($msg,$args);
          }

          if (headers_sent()) {
            dbg($msg,$this->debug_hidden);
          } elseif (!$this->debug_hidden) {
            msg($msg,0);
          }
          
          if ($this->debug_file) {
            dbglog($msg);
          }
      }
      
    }
  protected  function show_error($msg) {
      msg($msg,-1);  
    }
    
}
