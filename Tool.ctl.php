<?php

    ###########################
    ##  Common Code collect  ##
    ###########################

class Tool
{
    /**
     * 随机生成16位字符串
     * @return string 生成的字符串
     */
    function getRandomStr()
    {
        $str   = "";
        $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
        $max   = strlen($chars) - 1;
        for ($i = 0; $i < 16; $i++) {
            $str .= $chars[mt_rand(0, $max)];
        }

        return $str;
    }

    private function createNonceStr($length = 16)
    {
        $str   = "";
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $max   = strlen($chars) - 1;
        for ($i = 0; $i < $length; $i++) {
          $str .= substr($chars, mt_rand(0, $max), 1);
        }

        return $str;
    }


    /**
     * 验证短信验证码
     * @return bool
     */
    protected function illegalSMSCode($code, $mobile)
    {
        $sms_code = K::M('pdo/pdo')->fetch('
            SELECT `value`, `create_at`
            FROM `checkcode`
            WHERE `key` = "sms_code_waimai"
            AND `mtype` = "sms_code_waimai"
            AND `mobile` = "'.$mobile.'"
        ');

        if (! $sms_code
            || !isset($sms_code['value'])
            || (
                strtoupper($sms_code['value'])
                != strtoupper($code)
            )
        ) {
            return '短信验证码错误';
        } elseif (! isset($sms_code['create_at'])
            || (time() - strtotime($sms_code['create_at'])) > 300
        ) {
            return '短信验证码已过期';
        }

        return false;
    }

    /**
     * Member JWT
     */
    $member['jwt'] = (isset($params['jwt']) && $params['jwt']=='yes')
    ? K::M('tools/tool')->getJWTString([
        'uid' => $member['uid'],
        'nkn' => $member['nickname'],
    ]) : '';


    /**
     * 获取统一单位的距离
     * @param  [type] $distance 输入距离
     * @return [type] 统一单位的距离
     */
    protected function getUnifyDistance($distance)
    {
        $num = floatval($distance);
        $len = mb_strlen($num);
        $unit = strtolower(mb_substr($distance, $len));
        if ($unit == 'm') {
            return $num;
        } elseif ($unit == 'km') {
            return $num*1000;
        }
    }

    /**
     * 发送HTTP请求
     * @param $url string 请求的URL
     * @param $method int 请求的方法
     * @param null $body String POST请求的Body
     * @param int $times 当前重试的次数
     * @return array
     * @throws APIConnectionException
     */
    public function _request($url, $method, $body=null, $times=1)
    {
        $this->log("Send " . $method . " " . $url . ", body:" . $body . ", times:" . $times);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        // 设置User-Agent
        curl_setopt($ch, CURLOPT_USERAGENT, self::USER_AGENT);
        // 连接建立最长耗时
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, self::CONNECT_TIMEOUT);
        // 请求最长耗时
        curl_setopt($ch, CURLOPT_TIMEOUT, self::READ_TIMEOUT);
        // 设置SSL版本
        curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        // 如果报证书相关失败,可以考虑取消注释掉该行,强制指定证书版本
        //curl_setopt($ch, CURLOPT_SSL_CIPHER_LIST, 'TLSv1');
        // 设置Basic认证
        curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_setopt($ch, CURLOPT_USERPWD, $this->appKey . ":" . $this->masterSecret);
        // 设置Post参数
        if ($method === self::HTTP_POST) {
            curl_setopt($ch, CURLOPT_POST, true);
        } else if ($method === self::HTTP_DELETE || $method === self::HTTP_PUT) {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        }
        if (!is_null($body)) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        // 设置headers
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            'Connection: Keep-Alive'
        ));

        // 执行请求
        $output = curl_exec($ch);
        // 解析Response
        $response = array();
        $errorCode = curl_errno($ch);
        $this->log(array($output, $errorCode));
        if ($errorCode) {
            if ($errorCode === 28) {
                throw new APIConnectionException("Response timeout. Your request has probably be received by JPush Server,please check that whether need to be pushed again.", true);
            } else if ($errorCode === 56) {
                // resolve error[56 Problem (2) in the Chunked-Encoded data]
                throw new APIConnectionException("Response timeout, maybe cause by old CURL version. Your request has probably be received by JPush Server, please check that whether need to be pushed again.", true);
            } else if ($times >= $this->retryTimes) {
                throw new APIConnectionException("Connect timeout. Please retry later. Error:" . $errorCode . " " . curl_error($ch));
            } else {
                $this->log("Send " . $method . " " . $url . " fail, curl_code:" . $errorCode . ", body:" . $body . ", times:" . $times);
                $this->_request($url, $method, $body, ++$times);
            }
        } else {
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $header_text = substr($output, 0, $header_size);
            $body = substr($output, $header_size);
            $headers = array();
            foreach (explode("\r\n", $header_text) as $i => $line) {
                if (!empty($line)) {
                    if ($i === 0) {
                        $headers['http_code'] = $line;
                    } else if (strpos($line, ": ")) {
                        list ($key, $value) = explode(': ', $line);
                        $headers[$key] = $value;
                    }
                }
            }
            $response['headers'] = $headers;
            $response['body'] = $body;
            $response['http_code'] = $httpCode;
        }
        curl_close($ch);
        return $response;
    }


    # Wechat
    ## errorCode.php
    /**
     * error code 说明.
     * <ul>
     *    <li>-40001: 签名验证错误</li>
     *    <li>-40002: xml解析失败</li>
     *    <li>-40003: sha加密生成签名失败</li>
     *    <li>-40004: encodingAesKey 非法</li>
     *    <li>-40005: appid 校验错误</li>
     *    <li>-40006: aes 加密失败</li>
     *    <li>-40007: aes 解密失败</li>
     *    <li>-40008: 解密后得到的buffer非法</li>
     *    <li>-40009: base64加密失败</li>
     *    <li>-40010: base64解密失败</li>
     *    <li>-40011: 生成xml失败</li>
     * </ul>
     */
    class ErrorCode
    {
        public static $OK = 0;
        public static $ValidateSignatureError = -40001;
        public static $ParseXmlError = -40002;
        public static $ComputeSignatureError = -40003;
        public static $IllegalAesKey = -40004;
        public static $ValidateAppidError = -40005;
        public static $EncryptAESError = -40006;
        public static $DecryptAESError = -40007;
        public static $IllegalBuffer = -40008;
        public static $EncodeBase64Error = -40009;
        public static $DecodeBase64Error = -40010;
        public static $GenReturnXmlError = -40011;
    }

    ## Sha1.php
    include_once "errorCode.php";
    /**
     * SHA1 class
     * 计算公众平台的消息签名接口.
     */
    class SHA1
    {
    /**
     * 用SHA1算法生成安全签名
     * @param string $token 票据
     * @param string $timestamp 时间戳
     * @param string $nonce 随机字符串
     * @param string $encrypt 密文消息
     */
    public function getSHA1($token, $timestamp, $nonce, $encrypt_msg)
    {
        //排序
        try {
            $array = array($encrypt_msg, $token, $timestamp, $nonce);
            sort($array, SORT_STRING);
            $str = implode($array);
            return array(ErrorCode::$OK, sha1($str));
        } catch (Exception $e) {
            //print $e . "\n";
            return array(ErrorCode::$ComputeSignatureError, null);
        }
    }

    /**
     * 生成xml消息
     * @param string $encrypt 加密后的消息密文
     * @param string $signature 安全签名
     * @param string $timestamp 时间戳
     * @param string $nonce 随机字符串
     */
    public function generate($encrypt, $signature, $timestamp, $nonce)
    {
        $format = "
        <xml>
            <Encrypt><![CDATA[%s]]></Encrypt>
            <MsgSignature><![CDATA[%s]]></MsgSignature>
            <TimeStamp>%s</TimeStamp>
            <Nonce><![CDATA[%s]]></Nonce>
        </xml>";

        return sprintf($format, $encrypt, $signature, $timestamp, $nonce);
    }


    private function httpGet($url)
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 500);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($curl, CURLOPT_URL, $url);

        $res = curl_exec($curl);
        curl_close($curl);

        return $res;
  }

    /**
     * GET 请求
     * @param string $url
     */
    private function http_get($url)
    {
        $oCurl = curl_init();
        if (stripos($url, "https://" ) !== FALSE){
            curl_setopt($oCurl, CURLOPT_SSL_VERIFYPEER, FALSE);
            curl_setopt($oCurl, CURLOPT_SSL_VERIFYHOST, FALSE);
        }
        curl_setopt($oCurl, CURLOPT_URL, $url);
        curl_setopt($oCurl, CURLOPT_RETURNTRANSFER, 1);
        $sContent = curl_exec($oCurl);
        $aStatus  = curl_getinfo($oCurl);
        curl_close($oCurl );
        if (intval($aStatus ["http_code"]) == 200) {
            return $sContent;
        } else {
            return false;
        }
    }

    /**
     * POST 请求
     * @param string $url
     * @param array $param
     * @return string content
     */
    private function http_post($url, $param) {
        $oCurl = curl_init ();
        if (stripos ( $url, "https://" ) !== FALSE) {
            curl_setopt ( $oCurl, CURLOPT_SSL_VERIFYPEER, FALSE );
            curl_setopt ( $oCurl, CURLOPT_SSL_VERIFYHOST, false );
        }
        if (is_string ( $param )) {
            $strPOST = $param;
        } else {
            $aPOST = array ();
            foreach ( $param as $key => $val ) {
                $aPOST [] = $key . "=" . urlencode ( $val );
            }
            $strPOST = join ( "&", $aPOST );
        }
        curl_setopt ( $oCurl, CURLOPT_URL, $url );
        curl_setopt ( $oCurl, CURLOPT_RETURNTRANSFER, 1 );
        curl_setopt ( $oCurl, CURLOPT_POST, true );
        curl_setopt ( $oCurl, CURLOPT_POSTFIELDS, $strPOST );
        $sContent = curl_exec ( $oCurl );
        $aStatus = curl_getinfo ( $oCurl );
        curl_close ( $oCurl );
        if (intval ( $aStatus ["http_code"] ) == 200) {
            return $sContent;
        } else {
            return false;
        }
    }


    # Dir io
    public static function create($dir, $mode=0777, $makeindex=false)
    {
        $dir = rtrim(str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $dir), DIRECTORY_SEPARATOR);
        return self::mkdir($dir, $mode, $makeindex);
        //在php设置为base_dir的时候会出错改用self::mkdir递归来创建
        if(!file_exists($dir)){
            if(!$arr = explode(DIRECTORY_SEPARATOR, $dir)){
                return false;
            }
            $path = '';
            foreach ($arr as $k=>$v) {
                $path .= $v . DIRECTORY_SEPARATOR;
                if ($k > 0 && !file_exists($path)) {
                    mkdir($path);
                }
            }
        }
        return true;
    }

    public static function mkdir($dir, $mode = 0777, $makeindex = true)
    {
        if(!is_dir($dir)) {
            if(preg_match('/\.(asp|php|aspx|jsp|cgi)/i', $dir)){
                return false;
            }else if(preg_match('/;/i', $dir)){
                return false;
            }            
            self::mkdir(dirname($dir), $mode, $makeindex);
            @mkdir($dir, $mode);
            if(!empty($makeindex)) {
                @touch($dir.'/index.html'); @chmod($dir.'/index.html', 0777);
            }
        }
        return true;
    }

    public static function copy($source, $target, $over=false)
    {
        $source = rtrim(str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $source), DIRECTORY_SEPARATOR);
        $target = rtrim(str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $target), DIRECTORY_SEPARATOR);
        if (!is_dir($source)){
            return false;
        }
        if (!file_exists($target)){
            self::create($target);
        }
        if(!$handler = opendir($source)){
            return false;
        }
        while(false !== ($file = readdir($handler))){
            if ($file == '.' || $file == '..') {
                continue;
            }else if (is_dir($source.$file)) {
                self::copy($source.$file, $target.$file, $over);
            } else {
                 K::M('io/file')->copy($source.$file, $target.$file, $over);               
            }
        }
        return closedir($handler);        
    }

    public function move($source, $target, $over=false)
    {
        $source = rtrim(str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $source), DIRECTORY_SEPARATOR);
        $target = rtrim(str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $target), DIRECTORY_SEPARATOR);

        if (!is_dir($source)) {
            return false;
        }
        if (!file_exists($target)) {
            self::create($target);
        }
        if(!$handler = opendir($source)){
            return false;
        }
        while(false !== ($file = readdir($handler))){
            if($file == '.' || $file == '..'){
                continue;
            }
            if(is_dir($source.$file)){
                self::move($source.$file, $target.$file, $over);
            }else{
                K::M('io/file')->move($source.$file, $target.$file, $over);
            }
        }
        closedir($handler);
        return rmdir($source);
    }

    //注：危险指令慎用
    public static function remove($dir)
    {
        $dir = rtrim(str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $dir), DIRECTORY_SEPARATOR);
        if (!is_dir($dir)) {
            return false;
        }
        if(!$handler = opendir($dir)){
            return false;
        }
        while(false !== ($file = readdir($handler))){
            if($file == '.' || $file == '..') {
                continue;
            }
            if(is_dir($dir.$file)){
                self::remove($dir . $file);
            }else{
                K::M('io/file')->remove($dir.'/'.$file);
            }
        }
        closedir($handler);
        return rmdir($dir);
    }

    public function postMessageSend($data,$config)
    {
        //初始化
        $curl = curl_init();
        //设置抓取的url
        curl_setopt($curl, CURLOPT_URL, 'https://report.jpush.cn/v3/status/message');
        //设置头文件的信息作为数据流输出
        curl_setopt($curl, CURLOPT_HEADER, false);
        //设置获取的信息以文件流的形式返回，而不是直接输出。
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        // 设置SSL版本
        curl_setopt($curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        //设置头
        curl_setopt($curl, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json; charset=utf-8',
            'Authorization:' . base64_encode($config['key'].':'.$config['secret']),
        ]);
        //设置post方式提交
        curl_setopt($curl, CURLOPT_POST, 1);
        //设置post数据
        curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        //执行命令
        $data = curl_exec($curl);

        //var_dump(curl_error($curl));
        //var_dump(curl_errno($curl));

        //关闭URL请求
        curl_close($curl);
        //显示获得的数据
        return $data;
    }

    function liansuo_post($url,$data)
    {   // 模拟提交数据函数
        $curl = curl_init(); // 启动一个CURL会话
        curl_setopt($curl, CURLOPT_URL, $url); // 要访问的地址
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0); // 对认证证书来源的检测
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 1); // 从证书中检查SSL加密算法是否存在
        curl_setopt($curl, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']); // 模拟用户使用的浏览
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Expect:')); //解决数据包大不能提交
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1); // 使用自动跳转
        curl_setopt($curl, CURLOPT_AUTOREFERER, 1); // 自动设置Referer
        curl_setopt($curl, CURLOPT_POST, 1); // 发送一个常规的Post请求
        curl_setopt($curl, CURLOPT_POSTFIELDS, $data); // Post提交的数据包
        curl_setopt($curl, CURLOPT_COOKIEFILE, $GLOBALS['cookie_file']); // 读取上面所储存的Cookie信息
        curl_setopt($curl, CURLOPT_TIMEOUT, 30); // 设置超时限制防止死循
        curl_setopt($curl, CURLOPT_HEADER, 0); // 显示返回的Header区域内容
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1); // 获取的信息以文件流的形式返回

        $tmpInfo = curl_exec($curl); // 执行操作
        if (curl_errno($curl)) {
            echo 'Errno'.curl_error($curl);
        }
        curl_close($curl); // 关键CURL会话
        return $tmpInfo; // 返回数据
    }


    public function getJWTString($params = [])
    {
        $header  = base64_encode(json_encode([
            'typ' => 'JWT',
            'alg' => 'SHA256',
        ]));
        $claims = [
            'exp' => __TIME+604800,    // 1 week
            'nbf' => __TIME,
            'iat' => __TIME,
        ];
        $payload = base64_encode(json_encode(array_merge($params, $claims)));
        $signature  = base64_encode(hash_hmac('sha256', $header.'.'.$payload, __CFG::JWT_SECRET_KEY));

        return implode('.', [$header, $payload, $signature]);
    }

    public function mobileZhFormatIsWrong($mobile)
    {
        return !preg_match('/^1[34578]\d{9}$/u', $mobile);
    }

    // 生成一个二维码图片
    public function generateQRCodeImage(
        $content,
        $errorLevel = 'L',
        $pointSize = 10,
        $margin = 1
    ){
        if (!class_exists('QRcode')) {
            include_once __CORE_DIR.'libs/qrcode/phpqrcode.php';
        }

        QRcode::png($content, false, $errorLevel, $pointSize, $margin);

        exit;
    }

    // slow, not recommend
    public function mobileZhFormatCheck($mobile, $min = 130, $max = 189, $escape = [
        140, 142, 143, 144, 146, 148,
        160, 161, 162, 163, 164, 165, 166, 167, 168, 169,
        172, 174, 179,
    ]) {
        $mobile = intval($mobile);
        if (11 !== strlen($mobile)) {
            return false;
        }
        $operator = substr($mobile, 0, 3);
        if (in_array($operator, $escape)) {
            return false;
        }

        return ($operator>=$min && $operator<=$max);
    }

    public function postJsonApiByCurl($uri, $headers, $paramStr)
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL        => $uri,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_POST       => true,
            CURLOPT_POSTFIELDS => $paramStr,
            CURLOPT_RETURNTRANSFER => true,
        ]);
        $res = curl_exec($ch);

        $errNo  = curl_errno($ch);
        $errMsg = curl_error($ch);

        curl_close($ch);

        return [
            'errNo'  => $errNo,
            'errMsg' => $errMsg,
            'res'    => json_decode($res, true),
        ];
    }


    public function requestJsonApi($uri, $type = 'POST', $params = [])
    {
        $ch = curl_init();

        $setOpt = [
            CURLOPT_URL        => $uri,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json; Charset: UTF-8',
            ],
            CURLOPT_RETURNTRANSFER => true,
        ];

        if ('POST' == $type) {
            $setOpt = array_merge($setOpt, [
                CURLOPT_POST       => true,
                CURLOPT_POSTFIELDS => $params,
            ]);
        }

        curl_setopt_array($ch, $setOpt);

        $res = curl_exec($ch);

        $errNo  = curl_errno($ch);
        $errMsg = curl_error($ch);

        curl_close($ch);

        return [
            'err' => $errNo,
            'msg' => $errMsg,
            'res' => json_decode($res, true),
        ];
    }

    public function isTimestamp($timestamp)
    {
        return (
            is_integer($timestamp)
            && ($timestamp >= 0)
            && ($timestamp <= 2147472000)
        );
    }

    // array $data
    public function jsonResponse($data)
    {
        if (! headers_sent()) {
            header('Content-Type: application/json; charset=UTF-8');
        }

        echo json_encode(
            $data,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );

        exit;
    }

    public function log(
        $msg,
        $file = __FILE__,
        $line = __LINE__,
        $name = 'hcm_tool_log',
        $append = true
    ) {
        $path    = __CORE_DIR.'data/logs/';
        $logFile = $path.$name.'.php';
        $flag    = $append ? FILE_APPEND : LOCK_EX;
        $data    = <<< 'STR'
<?php exit('Access denied');?>
STR;
        $data   .= PHP_EOL.date('Y-m-d H:i:s').PHP_EOL
        .'=> '.$file
        .'#'.$line.PHP_EOL
        .'=> '.$msg
        .PHP_EOL.PHP_EOL;

        file_put_contents($logFile, $data, $flag);

        return $this;
    }
}