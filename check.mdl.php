<?php


class Mdl_Verify_Check
{

    public static function mail($mail)
    {
        if(strlen($mail)>6 && preg_match("/^[\w\-\.]+@[\w\-\.]+[\.\w]{2,}$/", $mail)){
            return $mail;
        }
        return false;
    }

    public static function phone($phone)
    {
        if(preg_match("/^((1[3,5,8,7]{1}[\d]{9})|(((400|800)-?(\d{3})-?(\d{4}))|^((\d{7,8})|(\d{4}|\d{3})-?(\d{7,8})|(\d{4}|\d{3})-(\d{3,7,8})-(\d{4}|\d{3}|\d{2}|\d{1})|(\d{7,8})-(\d{4}|\d{3}|\d{2}|\d{1}))$))$/", $phone)){
            return $phone;
        }
        return false;
        //return preg_match("/^(0?(([1-9]\d)|([3-9]\d{2}))-?)?\d{7,8}$/", $phone);
    }

    public static function mobile($mobile)
    {
        if(preg_match("/^1[3-8]\d{9}$/", $mobile)){
            return $mobile;
        }
        return false;
    }

    public static function number($number)
    {
        return is_numeric($number);
    }

    public static function ids($ids)
    {
        if(is_array($ids)){
            $ids = implode(',', $ids);
        }
        if(preg_match("/^(\d+|(\d([\d,]+?)\d))$/",$ids)){
            return $ids;
        }
        return false;
    }

    public static function url($url)
    {
        if(!preg_match('/^http[s]?:\/\/(([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9a-z_!~*\'()-]+\.)*([0-9a-z][0-9a-z-]{0,61})?[0-9a-z]\.[a-z]{2,6})(:[0-9]{1,4})?((\/\?)|(\/[0-9a-zA-Z_!~\*\'\(\)\.;\?:@&=\+\$,%#-\/]*)?)$/',  
        $url)){
            return false;
        }
        return $url;   
    }

    public static function qq($qq)
    {
        if(preg_match('/^\d{5,10}(\,\d{5,10})*$/', $qq)){
            return $qq;
        }
        return false;
    }

    public static function len($len, $min=null, $max=null)
    {
        if($min !== null && $len < $min){
            return false;
        }else if($max !== null && $len > $max){
            return false;
        }
        return true;
    }

    public static function id_number($id_number)
    {
        if(preg_match('/^\d{17}(\d|x)$/i', $id_number)  || preg_match('/^\d{15}$/i', $id_number)){
            return $id_number;
        }
        return false;
    }
}