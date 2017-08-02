<?php

namespace ParanoidCurl;

require_once __DIR__.'/../vendor/autoload.php';

use Ds\Set;


class ParanoidCurlException extends \Exception {}


class ParanoidCurl {

    protected static $DEFAULT_IP_BLACKLIST = [
        '0.0.0.0/8',
        '10.0.0.0/8',
        '100.64.0.0/10',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.0.0.0/29',
        '192.0.2.0/24',
        '192.88.99.0/24',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4',
        '240.0.0.0/4'
    ];
    protected static $DEFAULT_PORT_WHITELIST = [80, 443, 8080, 8443];

    public $ipWhitelist;
    public $ipBlacklist;
    public $portWhitelist;
    public $portBlacklist;
    public $detectLocalAddresses;
    public $throwErrors;

    public function __construct(
        $ipWhitelist = null,
        $ipBlacklist = null,
        $portWhitelist = null,
        $portBlacklist = null,
        $detectLocalAddresses = true,
        // We're trying to mimic the raw cURL interface as much
        // as possible, and that never throws.
        $throwErrors = false
    ) {
        if ($ipBlacklist === null)
            $ipBlacklist = $this::$DEFAULT_IP_BLACKLIST;
        if ($portWhitelist === null)
            $portWhitelist = $this::$DEFAULT_PORT_WHITELIST;

        $this->ipWhitelist = $this::_convertToSet($ipWhitelist);
        $this->ipBlacklist = $this::_convertToSet($ipBlacklist);
        $this->portWhitelist = $this::_convertToSet($portWhitelist);
        $this->portBlacklist = $this::_convertToSet($portBlacklist);
        $this->detectLocalAddresses = $detectLocalAddresses;
        $this->throwErrors = $throwErrors;
    }

    public function makeHandleParanoid($ch) {
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        // We can only safely support IPv4 for now.
        curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        curl_setopt($ch, CURLOPT_SOCKOPTFUNCTION, function($ch, $sock, $purpose) {
            return $this->_paranoidSockOpt($ch, $sock, $purpose);
        });
        curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, function($ch, $purpose, $address) {
            return $this->_paranoidOpenSocket($ch, $purpose, $address);
        });
    }

    public function curlExec($ch) {
        $this->makeHandleParanoid($ch);
        $res = curl_exec($ch);
        if ($this->throwErrors) {
            $blacklist_res = $this->getParanoidErr($ch);
            if ($blacklist_res) {
                throw new ParanoidCurlException($blacklist_res);
            }
        }
        return $res;
    }

    protected function _paranoidSockOpt($ch, $sock, $purpose) {
        // We need to return the error code here, as older versions of cURL will just
        // hang forever if you return an error code or invalid socket in the
        // `OPENSOCKET` callback.

        // Returning an error code here will always correctly abort the connection.
        return !!$this->getParanoidErr($ch);
    }

    protected function _paranoidOpenSocket($ch, $purpose, $address) {
        // Make sure we're not clobbering an existing `PRIVATE` field.
        assert(!$this->getParanoidErr($ch));
        $addr = $address['address'];
        $blacklist = null;

        if ($address['family'] !== AF_INET) {
            $blacklist = "Invalid address family {$address['family']}";
        } else if($address['socktype'] !== SOCK_STREAM) {
            $blacklist = "Invalid socket type {$address['socktype']}";
        } else if($address['protocol'] !== SOL_TCP) {
            $blacklist = "Invalid protocol {$address['protocol']}";
            // N.B.: Will only work for IPv4
        } else if(!$this->validatePort($addr[1])) {
            $blacklist = "Invalid port {$addr[1]}";
        } else if(!$this->validateIP($addr[0])) {
            $blacklist = "Invalid IP {$addr[0]}";
        }

        if ($blacklist) {
            $this->_setParanoidErr($ch, $blacklist);
            // We need to return a valid socket due to the bug noted in `_paranoidSockOpt` even though we
            // don't intend to use it. Just return a benign v4 tcp socket.
            // TODO: is there a way to return a neutered socket that could never be connected
            // just to be safe?
            $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        } else {
            $sock = socket_create($address['family'], $address['socktype'], $address['protocol']);
        }
        return $sock;
    }

    protected function _setParanoidErr($ch, $err) {
        // Use CURLOPT_PRIVATE to pass along blacklist context to the SOCKOPTFUNCTION handler
        curl_setopt($ch, CURLOPT_PRIVATE, $err);
    }

    public function getParanoidErr($ch) {
        $err = curl_getinfo($ch, CURLINFO_PRIVATE);
        if (!$err)
            return null;
        return $err;
    }

    public function validatePort($port) {
        if ($this->portWhitelist && !$this->portWhitelist->contains($port)) {
            return false;
        }
        if ($this->portBlacklist->contains($port)) {
            return false;
        }
        return true;
    }

    public function validateIP($ip) {
        // The explicit whitelist punches holes in the blacklist
        foreach($this->ipWhitelist as $cidr) {
            if($this::_cidrMatch($ip, $cidr)) {
                return true;
            }
        }
        foreach($this->ipBlacklist as $cidr) {
            if($this::_cidrMatch($ip, $cidr)) {
                return false;
            }
        }
        if ($this->detectLocalAddresses) {
            if ($this::_getLocalAddress() === $ip) {
                return false;
            }
        }
        return true;
    }

    /***
     * Convert array-like object to a Set, return a copy if passed in a Set instance
     * @param $obj Object to convert to a set
     * @return Set
     * @throws \Exception
     */
    protected static function _convertToSet($obj) {
        if ($obj === null) {
            return new Set();
        } else if ($obj instanceof Set || is_array($obj)) {
            return new Set($obj);
        }
        throw new \Exception("obj is not an array-like object: " . gettype($obj));
    }

    /***
     * Return the local IP of the interface used to connect to 8.8.8.8
     * Not foolproof, just meant to catch instances of addresses assigned
     * to adapters that aren't in the RFC1918 range.
     * @return string local IP address
     */
    protected static function _getLocalAddress() {
        // XXX: This is jank. Look for something like netifaces for Python.
        $name = null;
        $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        socket_connect($sock, "8.8.8.8", 53);
        socket_getsockname($sock, $name);
        return $name;
    }

    protected static function _cidrMatch($ip, $cidr) {
        // XXX: Need to make this work for IPv6
        list($subnet, $mask) = explode('/', $cidr);
        return (ip2long($ip) & ~((1 << (32 - $mask)) - 1) ) == ip2long($subnet);
    }
}