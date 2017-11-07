<?php

class LumenTool
{

    /**
     * @param $status int 状态码
     * @param $msg string 返回的信息
     * @param $data array 返回的数据
     * @return object
     */
    protected function responseJson($status,$msg,$data=[])
    {
        if (!is_numeric($status) || !is_string($msg)) {
            throw new \InvalidArgumentException('类型错误');
        }

        if (!empty($data)) {
            $array = [
                'errcode' => $status,
                'msg' => $msg,
                'data' => $data
            ];
        } else {
            $array = [
                'errcode' => $status,
                'msg' => $msg
            ];
        }

        return \App\Traits\Tool::jsonResp($array);
    }

    /**
     * 验证用户参数合法性
     * @param $params
     * @param $rules
     * @return boolean
     */
    protected function verifyUserParams($params,$rules)
    {
        if (!is_array($params)
            || empty($params)
            || !is_array($rules)
            || empty($rules)) {
            return false;
        }

        $validator = Validator::make($params, $rules);

        if ($validator->fails()) {
            $this->_msg = $validator->errors()->first();
            return false;
        }

        return true;
    }

        /**
     * @author phb
     * @desc 控制台函数调试
     * @param $data
     */
    function console($data,$flag=true){
        $stdout = fopen('php://stdout', 'w');
        if ($flag) {
            fwrite($stdout,json_encode($data)."\n");
        } else {
            fwrite($stdout,$data."\n");
        }
        fclose($stdout);
    }


    public function http($url, $params=array(), $method='POST')
    {
        if(!function_exists('curl_init')){
            throw new NotFoundHttpException('请安装curl扩展');
        }

        $http = curl_init();
        /* Curl settings */
        curl_setopt($http, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
        curl_setopt($http, CURLOPT_USERAGENT, $this->useragent);
        curl_setopt($http, CURLOPT_CONNECTTIMEOUT, $this->connect_timeout);
        curl_setopt($http, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($http, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($http, CURLOPT_ENCODING, "");
        curl_setopt($http, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($http, CURLOPT_HEADER, FALSE);

        $params = http_build_query($params);
        switch ($method) {
            case 'POST':
                curl_setopt($http, CURLOPT_POST, TRUE);
                if (!empty($params)) {
                    curl_setopt($http, CURLOPT_POSTFIELDS, $params);
                }
                break;
            case 'PUT' :
                curl_setopt($http, CURLOPT_PUT, true);
                if (!empty($params)) {
                    $url = strpos('?',$url)===false ? "{$url}?{$params}" : "{$url}&{$params}";
                }
                break;
            case 'DELETE':
                curl_setopt($http, CURLOPT_CUSTOMREQUEST, 'DELETE');
                if (!empty($params)) {
                    $url = strpos('?',$url)===false ? "{$url}?{$params}" : "{$url}&{$params}";
                }
                break;
            case 'GET':
                curl_setopt($http, CURLOPT_CUSTOMREQUEST, 'GET');
                if (!empty($params)) {
                    $url = strpos('?',$url)===false ? "{$url}?{$params}" : "{$url}&{$params}";
                }
        }

        $headers[] = "API-ClientIP: " . $_SERVER['REMOTE_ADDR'];

        curl_setopt($http, CURLOPT_URL, $url );
        curl_setopt($http, CURLOPT_HTTPHEADER, $headers );
        curl_setopt($http, CURLINFO_HEADER_OUT, TRUE );
        $res = curl_exec($http);

        // 检查是否有错误发生
        if(!curl_errno($http)) {
            $info = curl_getinfo($http);
        }

        curl_close($http);
        return $res;
    }

    /**
     * @desc 计算某个经纬度的周围某段距离的正方形的四个点
     * @param  lng float 经度
     * @param  lat float 纬度
     * @param  distance float 该点所在圆的半径，该圆与此正方形内切，默认值为0.5千米
     * @return array 正方形的四个点的经纬度坐标
     */

    public function returnSquarePoint($lng,$lat,$distance = 10)
    {
        $dlng =  2 * asin(sin($distance / (2 * self::EARTH_RADIUS)) / cos(deg2rad($lat)));
        $dlng = rad2deg($dlng);
        $dlat = $distance / self::EARTH_RADIUS;
        $dlat = rad2deg($dlat);
        return [
            'left-top' => ['lat'=> $lat + $dlat,'lng'=> $lng - $dlng],
            'right-top' => ['lat' => $lat + $dlat, 'lng' => $lng + $dlng],
            'left-bottom' => ['lat' => $lat - $dlat, 'lng' => $lng - $dlng],
            'right-bottom' => ['lat' => $lat - $dlat, 'lng' => $lng + $dlng]
        ];
    }


    //计算经纬度距离
    public function getDistance($lng1, $lat1, $lng2, $lat2)
    {
        //计算经纬度距离
        //将角度转为狐度
        $radLat1 = deg2rad($lat1);//deg2rad()函数将角度转换为弧度
        $radLat2 = deg2rad($lat2);
        $radLng1 = deg2rad($lng1);
        $radLng2 = deg2rad($lng2);
        $a = $radLat1 - $radLat2;
        $b = $radLng1 - $radLng2;
        $s = 2 * asin( sqrt ( pow (sin($a / 2),2) + cos($radLat1) * cos($radLat2) * pow(sin($b / 2),2) ) ) * 6378.137 * 1000;
        $s = round($s,2);

        return ($s < 1000) ? ( round($s, 2) . 'm') : round( intval($s / 1000).'.'.( $s % 1000), 2).'km';
    }

    // Generate inner system trade number
    // $mid: member id
    // $mtype: 01 => user; 02 => shop; 03 => staff; 04 => refund; ...
    // $domain: 00 => master

    public static function tradeNo(
        $mid = 0,
        $mtype = '01',
        $domain = '00'
    ): string
    {
        $domain  = str_pad(($domain%42), 2, '0', STR_PAD_LEFT);
        $mid     = str_pad(($mid%1024), 4, '0', STR_PAD_LEFT);
        $mtype   = in_array($mtype, ['01', '02', '03']) ? $mtype : '00';
        $postfix = mb_substr(microtime(), 2, 6);

        return date('YmdHis').$domain.$mtype.$mid.mt_rand(1000, 9999).$postfix;
    }

    public static function xmlToArray(string $xml)
    {
        return json_decode(json_encode(simplexml_load_string(
            $xml,
            'SimpleXMLElement',
            LIBXML_NOCDATA
        )), true);
    }

    public static function array2XML(array $array, string &$xml): string
    {
        foreach ($array as $key => &$val) {
            if (is_array($val)) {
                $_xml = '';
                $val = self::array2XML($val, $_xml);
            }
            $xml .= "<$key>$val</$key>";
        }

        unset($val);

        return $xml;
    }

    public static function arrayToXML(array $array, $xml = ''): string
    {
        $_xml  = '<?xml version="1.0" encoding="utf-8"?><xml>'
        .self::array2XML($array, $xml)
        .'</xml>';

        return $_xml;

    }

    public static function isTimestamp($timestamp): bool
    {
        return (
            is_integer($timestamp)
            && ($timestamp >= 0)
            && ($timestamp <= 2147472000)
        );
    }

    public static function jsonResp(
        array $data,
        int $status = 200,
        bool $unicode = true
    ) {
        $unicode = $unicode ? JSON_UNESCAPED_UNICODE : null;

        $data = json_encode($data, $unicode);

        return response($data)
        ->header('Content-Type', 'application/json; charset=utf-8');
    }
}