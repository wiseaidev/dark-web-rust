# Chapter 4: Web Reconnaissance in Rust

## Introduction

The year 2010 marked a pivotal moment in cybersecurity, witnessing the emergence of sophisticated cyber threats through events like [Operation Aurora](https://en.wikipedia.org/wiki/Operation_Aurora) and the [Stuxnet attack](https://en.wikipedia.org/wiki/Stuxnet). Operation Aurora targeted multinational businesses and Gmail accounts, while Stuxnet, a technologically advanced assault, focused on SCADA systems in Iran. Both incidents underscored the role of social engineering in facilitating infiltration, as highlighted by Constantin in 2012. Since then, the landscape of cybersecurity has continued to evolve, with notable recent attacks adding to the complexity of the threat landscape. Examples include the [SolarWinds supply chain attack](https://en.wikipedia.org/wiki/SolarWinds#SUNBURST) in 2020, where malicious actors compromised software updates to distribute malware, and the [Colonial Pipeline ransomware attack](https://en.wikipedia.org/wiki/Colonial_Pipeline_ransomware_attack) in 2021, which disrupted fuel supply in the United States. These incidents underscore the persistent relevance of social engineering and the ongoing need for robust cybersecurity measures in the face of ever-evolving cyber threats.

As we navigate the complexities of web reconnaissance, the enduring significance of the human element in cybersecurity becomes apparent. Regardless of the technological sophistication of cyber attacks, effective social engineering remains a critical force multiplier, amplifying the impact of these threats. In the following sections, we'll delve into how Rust, with its emphasis on memory safety and performance, can be leveraged to automate web reconnaissance and enhance social engineering attacks.

### 1. Web Exploration in Rust

In the world of web technologies, the ability to browse the Internet anonymously stands as a fundamental skill. Rust's [`Reqwest` library](https://docs.rs/reqwest), a powerful crate in the Rust ecosystem, provides the means to achieve this objective. In our exploration, we will delve into the details of utilizing `reqwest` for (anonymous) web browsing, underscoring the importance of comprehending the mechanisms governing online anonymity.

Rust Reqwest offers powerful capabilities for web interaction with a focus on performance and safety allowing for seamless manipulation of browser elements. An example script below showcases basic usage, retrieving and printing the HTML source code of a specified website:

```rust
use reqwest;

async fn fetch_page(url: &str) -> Result<(), reqwest::Error> {
    let body = reqwest::get(url)
        .await?
        .text()
        .await?;
    println!("{}", body);
    Ok(())
}

fn main() {
    fetch_page("http://www.google.com").await.unwrap();
}
```

In this script, Reqwest's `get` method retrieves the webpage, and the `text` method extracts the HTML source code. This foundational knowledge forms the basis for more advanced web reconnaissance techniques.


```Rust
:dep reqwest = { version="0.11.23", features=["cookies",] }
```


```Rust
use reqwest;

async fn fetch_page(url: &str) -> Result<(), reqwest::Error> {
    let body = reqwest::get(url)
        .await?
        .text()
        .await?;
    println!("{}", body);
    Ok(())
}

fetch_page("http://www.google.com").await.unwrap();
```

    <!doctype html><html dir="rtl" itemscope="" itemtype="http://schema.org/WebPage" lang="ar-LB"><head><meta content="text/html; charset=UTF-8" http-equiv="Content-Type"><meta content="/logos/doodles/2024/new-years-day-2024-6753651837110174-law.gif" itemprop="image"><meta content="&#1593;&#1610;&#1583; &#1585;&#1571;&#1587; &#1575;&#1604;&#1587;&#1606;&#1577; 2024" property="twitter:title"><meta content="&#1571;&#1591;&#1610;&#1576; &#1575;&#1604;&#1578;&#1605;&#1606;&#1610;&#1575;&#1578; &#1576;&#1605;&#1606;&#1575;&#1587;&#1576;&#1577; &#1593;&#1610;&#1583; &#1585;&#1571;&#1587; &#1575;&#1604;&#1587;&#1606;&#1577;. #GoogleDoodle" property="twitter:description"><meta content="&#1571;&#1591;&#1610;&#1576; &#1575;&#1604;&#1578;&#1605;&#1606;&#1610;&#1575;&#1578; &#1576;&#1605;&#1606;&#1575;&#1587;&#1576;&#1577; &#1593;&#1610;&#1583; &#1585;&#1571;&#1587; &#1575;&#1604;&#1587;&#1606;&#1577;. #GoogleDoodle" property="og:description"><meta content="summary_large_image" property="twitter:card"><meta content="@GoogleDoodles" property="twitter:site"><meta content="https://www.google.com/logos/doodles/2024/new-years-day-2024-6753651837110174-2xa.gif" property="twitter:image"><meta content="https://www.google.com/logos/doodles/2024/new-years-day-2024-6753651837110174-2xa.gif" property="og:image"><meta content="1000" property="og:image:width"><meta content="400" property="og:image:height"><meta content="https://www.google.com/logos/doodles/2024/new-years-day-2024-6753651837110174-2xa.gif" property="og:url"><meta content="video.other" property="og:type"><title>Google</title><script nonce="M2mhXcT2weLVc33PCU9lFg">(function(){var _g={kEI:'wXOSZb-CAoyNkdUP_7K2gAQ',kEXPI:'0,1365467,207,4804,1132070,1827,868710,327194,380759,16115,19397,9287,22431,1361,12311,2823,14765,4998,17075,38444,2872,2891,4140,7614,606,30668,30022,16105,230,20583,4,57402,2215,27038,6636,7596,1,42154,2,39761,6700,952,30169,4568,6256,23421,1252,33064,2,2,1,10957,15675,8155,23351,20506,7,1922,9779,8213,34246,2040,18159,20136,14,82,52946,2265,765,11151,4665,1804,21012,14256,11814,477,1158,42265,1744,5222489,2,225,72,68,1221,5993379,2803214,4251,7474661,5,16495897,4044107,16672,39684,4,4199,3,1603,3,262,3,234,3,2121276,2585,23029351,7954,1,4844,8408,10755,148,3797,1965,13023,4427,7460,3117,1805,4073,4240,10366,10078,6094,214,9213,2,1296,2052,27,6,5,15,265,5535,663,209,438,668,1686,77,2471,1551,6675,230,50,1042,1623,2855,2637,2424,2370,1252,961,149,2383,664,2084,79,1,6,2815,391,442,3302,994,551,769,1468,218,3,2060,255,39,271,2272,209,1129,3367,5,155,1286,720,91,717,625,814,1854,2,3,10,2,107,1146,1253,50,4,669,90,708,768,3,4,2,2,2,28,252,527,980,14,1,6,1063,92,880,591,283,248,1733,2688,2732,309,960,206,379,79,319,286,240,2,6,2,771,4,663,108,112,667,77,103,4,187,823,463,602,126,98,1,1,736,138,8,131,1511,85,25,190,568,2,679,1322,243,357,461,302,210,191,1772,35,624,682,45,83,429,442,237,63,2833,378,2,351,9,15,1299,191,28,289,4,24,359,2452,59,875,597,9,251,3,21732191,218,4005,5,274,752',kBL:'TMBp',kOPI:89978449};(function(){var a;(null==(a=window.google)?0:a.stvsc)?google.kEI=_g.kEI:window.google=_g;}).call(this);})();(function(){google.sn='webhp';google.kHL='ar-LB';})();(function(){
    var h=this||self;function l(){return void 0!==window.google&&void 0!==window.google.kOPI&&0!==window.google.kOPI?window.google.kOPI:null};var m,n=[];function p(a){for(var b;a&&(!a.getAttribute||!(b=a.getAttribute("eid")));)a=a.parentNode;return b||m}function q(a){for(var b=null;a&&(!a.getAttribute||!(b=a.getAttribute("leid")));)a=a.parentNode;return b}function r(a){/^http:/i.test(a)&&"https:"===window.location.protocol&&(google.ml&&google.ml(Error("a"),!1,{src:a,glmm:1}),a="");return a}
    function t(a,b,c,d,k){var e="";-1===b.search("&ei=")&&(e="&ei="+p(d),-1===b.search("&lei=")&&(d=q(d))&&(e+="&lei="+d));d="";var g=-1===b.search("&cshid=")&&"slh"!==a,f=[];f.push(["zx",Date.now().toString()]);h._cshid&&g&&f.push(["cshid",h._cshid]);c=c();null!=c&&f.push(["opi",c.toString()]);for(c=0;c<f.length;c++){if(0===c||0<c)d+="&";d+=f[c][0]+"="+f[c][1]}return"/"+(k||"gen_204")+"?atyp=i&ct="+String(a)+"&cad="+(b+e+d)};m=google.kEI;google.getEI=p;google.getLEI=q;google.ml=function(){return null};google.log=function(a,b,c,d,k,e){e=void 0===e?l:e;c||(c=t(a,b,e,d,k));if(c=r(c)){a=new Image;var g=n.length;n[g]=a;a.onerror=a.onload=a.onabort=function(){delete n[g]};a.src=c}};google.logUrl=function(a,b){b=void 0===b?l:b;return t("",a,b)};}).call(this);(function(){google.y={};google.sy=[];google.x=function(a,b){if(a)var c=a.id;else{do c=Math.random();while(google.y[c])}google.y[c]=[a,b];return!1};google.sx=function(a){google.sy.push(a)};google.lm=[];google.plm=function(a){google.lm.push.apply(google.lm,a)};google.lq=[];google.load=function(a,b,c){google.lq.push([[a],b,c])};google.loadAll=function(a,b){google.lq.push([a,b])};google.bx=!1;google.lx=function(){};var d=[];google.fce=function(a,b,c,e){d.push([a,b,c,e])};google.qce=d;}).call(this);google.f={};(function(){
    document.documentElement.addEventListener("submit",function(b){var a;if(a=b.target){var c=a.getAttribute("data-submitfalse");a="1"===c||"q"===c&&!a.elements.q.value?!0:!1}else a=!1;a&&(b.preventDefault(),b.stopPropagation())},!0);document.documentElement.addEventListener("click",function(b){var a;a:{for(a=b.target;a&&a!==document.documentElement;a=a.parentElement)if("A"===a.tagName){a="1"===a.getAttribute("data-nohref");break a}a=!1}a&&b.preventDefault()},!0);}).call(this);</script><style>#gb{font:13px/27px Arial,sans-serif;height:30px}#gbz,#gbg{position:absolute;white-space:nowrap;top:0;height:30px;z-index:1000}#gbz{right:0;padding-right:4px}#gbg{left:0;padding-left:5px}#gbs{background:transparent;position:absolute;top:-999px;visibility:hidden;z-index:998;left:0}.gbto #gbs{background:#fff}#gbx3,#gbx4{background-color:#2d2d2d;background-image:none;_background-image:none;background-position:0 -138px;background-repeat:repeat-x;border-bottom:1px solid #000;font-size:24px;height:29px;_height:30px;opacity:1;filter:alpha(opacity=100);position:absolute;top:0;width:100%;z-index:990}#gbx3{right:0}#gbx4{left:0}#gbb{position:relative}#gbbw{right:0;position:absolute;top:30px;width:100%}.gbtcb{position:absolute;visibility:hidden}#gbz .gbtcb{left:0}#gbg .gbtcb{right:0}.gbxx{display:none !important}.gbxo{opacity:0 !important;filter:alpha(opacity=0) !important}.gbm{position:absolute;z-index:999;top:-999px;visibility:hidden;text-align:right;border:1px solid #bebebe;background:#fff;-moz-box-shadow:-1px 1px 1px rgba(0,0,0,.2);-webkit-box-shadow:0 2px 4px rgba(0,0,0,.2);box-shadow:0 2px 4px rgba(0,0,0,.2)}.gbrtl .gbm{-moz-box-shadow:1px 1px 1px rgba(0,0,0,.2)}.gbto .gbm,.gbto #gbs{top:29px;visibility:visible}#gbz .gbm{right:0}#gbg .gbm{left:0}.gbxms{background-color:#ccc;display:block;position:absolute;z-index:1;top:-1px;right:-2px;left:-2px;bottom:-2px;opacity:.4;-moz-border-radius:3px;filter:progid:DXImageTransform.Microsoft.Blur(pixelradius=5);*opacity:1;*top:-2px;*right:-5px;*left:5px;*bottom:4px;-ms-filter:"progid:DXImageTransform.Microsoft.Blur(pixelradius=5)";opacity:1\0/;top:-4px\0/;right:-6px\0/;left:5px\0/;bottom:4px\0/}.gbma{position:relative;top:-1px;border-style:solid dashed dashed;border-color:transparent;border-top-color:#c0c0c0;display:-moz-inline-box;display:inline-block;font-size:0;height:0;line-height:0;width:0;border-width:3px 3px 0;padding-top:1px;right:4px}#gbztms1,#gbi4m1,#gbi4s,#gbi4t{zoom:1}.gbtc,.gbmc,.gbmcc{display:block;list-style:none;margin:0;padding:0}.gbmc{background:#fff;padding:10px 0;position:relative;z-index:2;zoom:1}.gbt{position:relative;display:-moz-inline-box;display:inline-block;line-height:27px;padding:0;vertical-align:top}.gbt{*display:inline}.gbto{box-shadow:0 2px 4px rgba(0,0,0,.2);-moz-box-shadow:0 2px 4px rgba(0,0,0,.2);-webkit-box-shadow:0 2px 4px rgba(0,0,0,.2)}.gbzt,.gbgt{cursor:pointer;display:block;text-decoration:none !important}span#gbg6,span#gbg4{cursor:default}.gbts{border-left:1px solid transparent;border-right:1px solid transparent;display:block;*display:inline-block;padding:0 5px;position:relative;z-index:1000}.gbts{*display:inline}.gbzt .gbts{display:inline;zoom:1}.gbto .gbts{background:#fff;border-color:#bebebe;color:#36c;padding-bottom:1px;padding-top:2px}.gbz0l .gbts{color:#fff;font-weight:bold}.gbtsa{padding-left:9px}#gbz .gbzt,#gbz .gbgt,#gbg .gbgt{color:#ccc!important}.gbtb2{display:block;border-top:2px solid transparent}.gbto .gbzt .gbtb2,.gbto .gbgt .gbtb2{border-top-width:0}.gbtb .gbts{background:url(https://ssl.gstatic.com/gb/images/b_8d5afc09.png);_background:url(https://ssl.gstatic.com/gb/images/b8_3615d64d.png);background-position:-27px -22px;border:0;font-size:0;padding:29px 0 0;*padding:27px 0 0;width:1px}.gbzt:hover,.gbzt:focus,.gbgt-hvr,.gbgt:focus{background-color:#4c4c4c;background-image:none;_background-image:none;background-position:0 -102px;background-repeat:repeat-x;outline:none;text-decoration:none !important}.gbpdjs .gbto .gbm{min-width:99%}.gbz0l .gbtb2{border-top-color:#dd4b39!important}#gbi4s,#gbi4s1{font-weight:bold}#gbg6.gbgt-hvr,#gbg6.gbgt:focus{background-color:transparent;background-image:none}.gbg4a{font-size:0;line-height:0}.gbg4a .gbts{padding:27px 5px 0;*padding:25px 5px 0}.gbto .gbg4a .gbts{padding:29px 5px 1px;*padding:27px 5px 1px}#gbi4i,#gbi4id{right:5px;border:0;height:24px;position:absolute;top:1px;width:24px}.gbto #gbi4i,.gbto #gbi4id{top:3px}.gbi4p{display:block;width:24px}#gbi4id{background-position:-44px -101px}#gbmpid{background-position:0 0}#gbmpi,#gbmpid{border:none;display:inline-block;height:48px;width:48px}#gbmpiw{display:inline-block;line-height:9px;padding-right:20px;margin-top:10px;position:relative}#gbmpi,#gbmpid,#gbmpiw{*display:inline}#gbg5{font-size:0}#gbgs5{padding:5px !important}.gbto #gbgs5{padding:7px 5px 6px !important}#gbi5{background:url(https://ssl.gstatic.com/gb/images/b_8d5afc09.png);_background:url(https://ssl.gstatic.com/gb/images/b8_3615d64d.png);background-position:0 0;display:block;font-size:0;height:17px;width:16px}.gbto #gbi5{background-position:-6px -22px}.gbn .gbmt,.gbn .gbmt:visited,.gbnd .gbmt,.gbnd .gbmt:visited{color:#dd8e27 !important}.gbf .gbmt,.gbf .gbmt:visited{color:#900 !important}.gbmt,.gbml1,.gbmlb,.gbmt:visited,.gbml1:visited,.gbmlb:visited{color:#36c !important;text-decoration:none !important}.gbmt,.gbmt:visited{display:block}.gbml1,.gbmlb,.gbml1:visited,.gbmlb:visited{display:inline-block;margin:0 10px}.gbml1,.gbmlb,.gbml1:visited,.gbmlb:visited{*display:inline}.gbml1,.gbml1:visited{padding:0 10px}.gbml1-hvr,.gbml1:focus{outline:none;text-decoration:underline !important}#gbpm .gbml1{display:inline;margin:0;padding:0;white-space:nowrap}.gbmlb,.gbmlb:visited{line-height:27px}.gbmlb-hvr,.gbmlb:focus{outline:none;text-decoration:underline !important}.gbmlbw{color:#ccc;margin:0 10px}.gbmt{padding:0 20px}.gbmt:hover,.gbmt:focus{background:#eee;cursor:pointer;outline:0 solid black;text-decoration:none !important}.gbm0l,.gbm0l:visited{color:#000 !important;font-weight:bold}.gbmh{border-top:1px solid #bebebe;font-size:0;margin:10px 0}#gbd4 .gbmc{background:#f5f5f5;padding-top:0}#gbd4 .gbsbic::-webkit-scrollbar-track:vertical{background-color:#f5f5f5;margin-top:2px}#gbmpdv{background:#fff;border-bottom:1px solid #bebebe;-moz-box-shadow:0 2px 4px rgba(0,0,0,.12);-o-box-shadow:0 2px 4px rgba(0,0,0,.12);-webkit-box-shadow:0 2px 4px rgba(0,0,0,.12);box-shadow:0 2px 4px rgba(0,0,0,.12);position:relative;z-index:1}#gbd4 .gbmh{margin:0}.gbmtc{padding:0;margin:0;line-height:27px}.GBMCC:last-child:after,#GBMPAL:last-child:after{content:'\0A\0A';white-space:pre;position:absolute}#gbmps{*zoom:1}#gbd4 .gbpc,#gbmpas .gbmt{line-height:17px}#gbd4 .gbpgs .gbmtc{line-height:27px}#gbd4 .gbmtc{border-bottom:1px solid #bebebe}#gbd4 .gbpc{display:inline-block;margin:16px 0 10px;padding-left:50px;vertical-align:top}#gbd4 .gbpc{*display:inline}.gbpc .gbps,.gbpc .gbps2{display:block;margin:0 20px}#gbmplp.gbps{margin:0 10px}.gbpc .gbps{color:#000;font-weight:bold}.gbpc .gbpd{margin-bottom:5px}.gbpd .gbmt,.gbpd .gbps{color:#666 !important}.gbpd .gbmt{opacity:.4;filter:alpha(opacity=40)}.gbps2{color:#666;display:block}.gbp0{display:none}.gbp0 .gbps2{font-weight:bold}#gbd4 .gbmcc{margin-top:5px}.gbpmc{background:#fef9db}.gbpmc .gbpmtc{padding:10px 20px}#gbpm{border:0;*border-collapse:collapse;border-spacing:0;margin:0;white-space:normal}#gbpm .gbpmtc{border-top:none;color:#000 !important;font:11px Arial,sans-serif}#gbpms{*white-space:nowrap}.gbpms2{font-weight:bold;white-space:nowrap}#gbmpal{*border-collapse:collapse;border-spacing:0;border:0;margin:0;white-space:nowrap;width:100%}.gbmpala,.gbmpalb{font:13px Arial,sans-serif;line-height:27px;padding:10px 20px 0;white-space:nowrap}.gbmpala{padding-right:0;text-align:right}.gbmpalb{padding-left:0;text-align:left}#gbmpasb .gbps{color:#000}#gbmpal .gbqfbb{margin:0 20px}.gbp0 .gbps{*display:inline}a.gbiba{margin:8px 20px 10px}.gbmpiaw{display:inline-block;padding-left:10px;margin-bottom:6px;margin-top:10px}.gbxv{visibility:hidden}.gbmpiaa{display:block;margin-top:10px}.gbmpia{border:none;display:block;height:48px;width:48px}.gbmpnw{display:inline-block;height:auto;margin:10px 0;vertical-align:top}
    .gbqfb,.gbqfba,.gbqfbb{-moz-border-radius:2px;-webkit-border-radius:2px;border-radius:2px;cursor:default !important;display:inline-block;font-weight:bold;height:29px;line-height:29px;min-width:54px;*min-width:70px;padding:0 8px;text-align:center;text-decoration:none !important;-moz-user-select:none;-webkit-user-select:none}.gbqfb:focus,.gbqfba:focus,.gbqfbb:focus{border:1px solid #4d90fe;-moz-box-shadow:inset 0 0 0 1px rgba(255, 255, 255, 0.5);-webkit-box-shadow:inset 0 0 0 1px rgba(255, 255, 255, 0.5);box-shadow:inset 0 0 0 1px rgba(255, 255, 255, 0.5);outline:none}.gbqfb-hvr:focus,.gbqfba-hvr:focus,.gbqfbb-hvr:focus{-webkit-box-shadow:inset 0 0 0 1px #fff,0 1px 1px rgba(0,0,0,.1);-moz-box-shadow:inset 0 0 0 1px #fff,0 1px 1px rgba(0,0,0,.1);box-shadow:inset 0 0 0 1px #fff,0 1px 1px rgba(0,0,0,.1)}.gbqfb-no-focus:focus{border:1px solid #3079ed;-moz-box-shadow:none;-webkit-box-shadow:none;box-shadow:none}.gbqfb-hvr,.gbqfba-hvr,.gbqfbb-hvr{-webkit-box-shadow:0 1px 1px rgba(0,0,0,.1);-moz-box-shadow:0 1px 1px rgba(0,0,0,.1);box-shadow:0 1px 1px rgba(0,0,0,.1)}.gbqfb::-moz-focus-inner,.gbqfba::-moz-focus-inner,.gbqfbb::-moz-focus-inner{border:0}.gbqfba,.gbqfbb{border:1px solid #dcdcdc;border-color:rgba(0,0,0,.1);color:#444 !important;font-size:11px}.gbqfb{background-color:#4d90fe;background-image:-webkit-gradient(linear,left top,left bottom,from(#4d90fe),to(#4787ed));background-image:-webkit-linear-gradient(top,#4d90fe,#4787ed);background-image:-moz-linear-gradient(top,#4d90fe,#4787ed);background-image:-ms-linear-gradient(top,#4d90fe,#4787ed);background-image:-o-linear-gradient(top,#4d90fe,#4787ed);background-image:linear-gradient(top,#4d90fe,#4787ed);filter:progid:DXImageTransform.Microsoft.gradient(startColorStr='#4d90fe',EndColorStr='#4787ed');border:1px solid #3079ed;color:#fff!important;margin:0 0}.gbqfb-hvr{border-color:#2f5bb7}.gbqfb-hvr:focus{border-color:#2f5bb7}.gbqfb-hvr,.gbqfb-hvr:focus{background-color:#357ae8;background-image:-webkit-gradient(linear,left top,left bottom,from(#4d90fe),to(#357ae8));background-image:-webkit-linear-gradient(top,#4d90fe,#357ae8);background-image:-moz-linear-gradient(top,#4d90fe,#357ae8);background-image:-ms-linear-gradient(top,#4d90fe,#357ae8);background-image:-o-linear-gradient(top,#4d90fe,#357ae8);background-image:linear-gradient(top,#4d90fe,#357ae8)}.gbqfb:active{background-color:inherit;-webkit-box-shadow:inset 0 1px 2px rgba(0, 0, 0, 0.3);-moz-box-shadow:inset 0 1px 2px rgba(0, 0, 0, 0.3);box-shadow:inset 0 1px 2px rgba(0, 0, 0, 0.3)}.gbqfba{background-color:#f5f5f5;background-image:-webkit-gradient(linear,left top,left bottom,from(#f5f5f5),to(#f1f1f1));background-image:-webkit-linear-gradient(top,#f5f5f5,#f1f1f1);background-image:-moz-linear-gradient(top,#f5f5f5,#f1f1f1);background-image:-ms-linear-gradient(top,#f5f5f5,#f1f1f1);background-image:-o-linear-gradient(top,#f5f5f5,#f1f1f1);background-image:linear-gradient(top,#f5f5f5,#f1f1f1);filter:progid:DXImageTransform.Microsoft.gradient(startColorStr='#f5f5f5',EndColorStr='#f1f1f1')}.gbqfba-hvr,.gbqfba-hvr:active{background-color:#f8f8f8;background-image:-webkit-gradient(linear,left top,left bottom,from(#f8f8f8),to(#f1f1f1));background-image:-webkit-linear-gradient(top,#f8f8f8,#f1f1f1);background-image:-moz-linear-gradient(top,#f8f8f8,#f1f1f1);background-image:-ms-linear-gradient(top,#f8f8f8,#f1f1f1);background-image:-o-linear-gradient(top,#f8f8f8,#f1f1f1);background-image:linear-gradient(top,#f8f8f8,#f1f1f1);filter:progid:DXImageTransform.Microsoft.gradient(startColorStr='#f8f8f8',EndColorStr='#f1f1f1')}.gbqfbb{background-color:#fff;background-image:-webkit-gradient(linear,left top,left bottom,from(#fff),to(#fbfbfb));background-image:-webkit-linear-gradient(top,#fff,#fbfbfb);background-image:-moz-linear-gradient(top,#fff,#fbfbfb);background-image:-ms-linear-gradient(top,#fff,#fbfbfb);background-image:-o-linear-gradient(top,#fff,#fbfbfb);background-image:linear-gradient(top,#fff,#fbfbfb);filter:progid:DXImageTransform.Microsoft.gradient(startColorStr='#ffffff',EndColorStr='#fbfbfb')}.gbqfbb-hvr,.gbqfbb-hvr:active{background-color:#fff;background-image:-webkit-gradient(linear,left top,left bottom,from(#fff),to(#f8f8f8));background-image:-webkit-linear-gradient(top,#fff,#f8f8f8);background-image:-moz-linear-gradient(top,#fff,#f8f8f8);background-image:-ms-linear-gradient(top,#fff,#f8f8f8);background-image:-o-linear-gradient(top,#fff,#f8f8f8);background-image:linear-gradient(top,#fff,#f8f8f8);filter:progid:DXImageTransform.Microsoft.gradient(startColorStr='#ffffff',EndColorStr='#f8f8f8')}.gbqfba-hvr,.gbqfba-hvr:active,.gbqfbb-hvr,.gbqfbb-hvr:active{border-color:#c6c6c6;-webkit-box-shadow:0 1px 1px rgba(0,0,0,.1);-moz-box-shadow:0 1px 1px rgba(0,0,0,.1);box-shadow:0 1px 1px rgba(0,0,0,.1);color:#222 !important}.gbqfba:active,.gbqfbb:active{-webkit-box-shadow:inset 0 1px 2px rgba(0,0,0,.1);-moz-box-shadow:inset 0 1px 2px rgba(0,0,0,.1);box-shadow:inset 0 1px 2px rgba(0,0,0,.1)}
    #gbmpas{max-height:220px}#gbmm{max-height:530px}.gbsb{-webkit-box-sizing:border-box;display:block;position:relative;*zoom:1}.gbsbic{overflow:auto}.gbsbis .gbsbt,.gbsbis .gbsbb{-webkit-mask-box-image:-webkit-gradient(linear,left top,right top,color-stop(0,rgba(0,0,0,.1)),color-stop(.5,rgba(0,0,0,.8)),color-stop(1,rgba(0,0,0,.1)));left:0;margin-right:0;opacity:0;position:absolute;width:100%}.gbsb .gbsbt:after,.gbsb .gbsbb:after{content:"";display:block;height:0;left:0;position:absolute;width:100%}.gbsbis .gbsbt{background:-webkit-gradient(linear,left top,left bottom,from(rgba(0,0,0,.2)),to(rgba(0,0,0,0)));background-image:-webkit-linear-gradient(top,rgba(0,0,0,.2),rgba(0,0,0,0));background-image:-moz-linear-gradient(top,rgba(0,0,0,.2),rgba(0,0,0,0));background-image:-ms-linear-gradient(top,rgba(0,0,0,.2),rgba(0,0,0,0));background-image:-o-linear-gradient(top,rgba(0,0,0,.2),rgba(0,0,0,0));background-image:linear-gradient(top,rgba(0,0,0,.2),rgba(0,0,0,0));height:6px;top:0}.gbsb .gbsbt:after{border-top:1px solid #ebebeb;border-color:rgba(0,0,0,.3);top:0}.gbsb .gbsbb{-webkit-mask-box-image:-webkit-gradient(linear,left top,right top,color-stop(0,rgba(0,0,0,.1)),color-stop(.5,rgba(0,0,0,.8)),color-stop(1,rgba(0,0,0,.1)));background:-webkit-gradient(linear,left bottom,left top,from(rgba(0,0,0,.2)),to(rgba(0,0,0,0)));background-image:-webkit-linear-gradient(bottom,rgba(0,0,0,.2),rgba(0,0,0,0));background-image:-moz-linear-gradient(bottom,rgba(0,0,0,.2),rgba(0,0,0,0));background-image:-ms-linear-gradient(bottom,rgba(0,0,0,.2),rgba(0,0,0,0));background-image:-o-linear-gradient(bottom,rgba(0,0,0,.2),rgba(0,0,0,0));background-image:linear-gradient(bottom,rgba(0,0,0,.2),rgba(0,0,0,0));bottom:0;height:4px}.gbsb .gbsbb:after{border-bottom:1px solid #ebebeb;border-color:rgba(0,0,0,.3);bottom:0}
    </style><style>body,td,a,p,.h{font-family:arial,sans-serif}body{margin:0;overflow-y:scroll}#gog{padding:3px 8px 0}td{line-height:.8em}.gac_m td{line-height:17px}form{margin-bottom:20px}.h{color:#1967d2}em{font-weight:bold;font-style:normal}.lst{height:25px;width:496px}.gsfi,.lst{font:18px arial,sans-serif}.gsfs{font:17px arial,sans-serif}.ds{display:inline-box;display:inline-block;margin:3px 0 4px;margin-right:4px}input{font-family:inherit}body{background:#fff;color:#000}a{color:#681da8;text-decoration:none}a:hover,a:active{text-decoration:underline}.fl a{color:#1967d2}a:visited{color:#681da8}.sblc{padding-top:5px}.sblc a{display:block;margin:2px 0;margin-right:13px;font-size:11px}.lsbb{background:#f8f9fa;border:solid 1px;border-color:#dadce0 #dadce0 #70757a #70757a;height:30px}.lsbb{display:block}#WqQANb a{display:inline-block;margin:0 12px}.lsb{background:url(/images/nav_logo229.png) 0 -261px repeat-x;color:#000;border:none;cursor:pointer;height:30px;margin:0;outline:0;font:15px arial,sans-serif;vertical-align:top}.lsb:active{background:#dadce0}.lst:focus{outline:none}.Ucigb{width:458px}</style><script nonce="M2mhXcT2weLVc33PCU9lFg">(function(){window.google.erd={jsr:1,bv:1919,de:true};
    var h=this||self;var k,l=null!=(k=h.mei)?k:1,n,p=null!=(n=h.sdo)?n:!0,q=0,r,t=google.erd,v=t.jsr;google.ml=function(a,b,d,m,e){e=void 0===e?2:e;b&&(r=a&&a.message);void 0===d&&(d={});d.cad="ple_"+google.ple+".aple_"+google.aple;if(google.dl)return google.dl(a,e,d),null;if(0>v){window.console&&console.error(a,d);if(-2===v)throw a;b=!1}else b=!a||!a.message||"Error loading script"===a.message||q>=l&&!m?!1:!0;if(!b)return null;q++;d=d||{};b=encodeURIComponent;var c="/gen_204?atyp=i&ei="+b(google.kEI);google.kEXPI&&(c+="&jexpid="+b(google.kEXPI));c+="&srcpg="+b(google.sn)+"&jsr="+b(t.jsr)+"&bver="+
    b(t.bv);var f=a.lineNumber;void 0!==f&&(c+="&line="+f);var g=a.fileName;g&&(0<g.indexOf("-extension:/")&&(e=3),c+="&script="+b(g),f&&g===window.location.href&&(f=document.documentElement.outerHTML.split("\n")[f],c+="&cad="+b(f?f.substring(0,300):"No script found.")));google.ple&&1===google.ple&&(e=2);c+="&jsel="+e;for(var u in d)c+="&",c+=b(u),c+="=",c+=b(d[u]);c=c+"&emsg="+b(a.name+": "+a.message);c=c+"&jsst="+b(a.stack||"N/A");12288<=c.length&&(c=c.substr(0,12288));a=c;m||google.log(0,"",a);return a};window.onerror=function(a,b,d,m,e){r!==a&&(a=e instanceof Error?e:Error(a),void 0===d||"lineNumber"in a||(a.lineNumber=d),void 0===b||"fileName"in a||(a.fileName=b),google.ml(a,!1,void 0,!1,"SyntaxError"===a.name||"SyntaxError"===a.message.substring(0,11)||-1!==a.message.indexOf("Script error")?3:0));r=null;p&&q>=l&&(window.onerror=null)};})();(function(){try{/*
    
     Copyright The Closure Library Authors.
     SPDX-License-Identifier: Apache-2.0
    */
    var e=this||self;var aa=function(a,b,c,d){d=d||{};d._sn=["cfg",b,c].join(".");window.gbar.logger.ml(a,d)};var f=window.gbar=window.gbar||{},h=window.gbar.i=window.gbar.i||{},da;function _tvn(a,b){a=parseInt(a,10);return isNaN(a)?b:a}function _tvf(a,b){a=parseFloat(a);return isNaN(a)?b:a}function _tvv(a){return!!a}function n(a,b,c){(c||f)[a]=b}f.bv={n:_tvn("2",0),r:"",f:".66.",e:"",m:_tvn("1",1)};
    function ea(a,b,c){var d="on"+b;if(a.addEventListener)a.addEventListener(b,c,!1);else if(a.attachEvent)a.attachEvent(d,c);else{var g=a[d];a[d]=function(){var k=g.apply(this,arguments),m=c.apply(this,arguments);return void 0==k?m:void 0==m?k:m&&k}}}var fa=function(a){return function(){return f.bv.m==a}},ha=fa(1),ia=fa(2);n("sb",ha);n("kn",ia);h.a=_tvv;h.b=_tvf;h.c=_tvn;h.i=aa;var q=window.gbar.i.i;var r=function(){},u=function(){},la=function(a){var b=new Image,c=ja;b.onerror=b.onload=b.onabort=function(){try{delete ka[c]}catch(d){}};ka[c]=b;b.src=a;ja=c+1},ka=[],ja=0;n("logger",{il:u,ml:r,log:la});var v=window.gbar.logger;var w={},x={createScript:function(a){return a}};x=self.trustedTypes&&self.trustedTypes.createPolicy?self.trustedTypes.createPolicy("ogb#inline",x):x;
    var ma={},y=[],na=h.b("0.1",.1),oa=h.a("1",!0),pa=function(a,b){y.push([a,b])},qa=function(a,b){w[a]=b},ra=function(a){return a in w},z={},A=function(a,b){z[a]||(z[a]=[]);z[a].push(b)},B=function(a){A("m",a)},C=function(a,b){var c=document.createElement("script");c.src=x.createScript(a);c.async=oa;Math.random()<na&&(c.onerror=function(){c.onerror=null;r(Error("Bundle load failed: name="+(b||"UNK")+" url="+a))});(document.getElementById("xjsc")||
    document.getElementsByTagName("body")[0]||document.getElementsByTagName("head")[0]).appendChild(c)},F=function(a){for(var b,c=0;(b=y[c])&&b[0]!=a;++c);!b||b[1].l||b[1].s||(b[1].s=!0,D(2,a),b[1].url&&C(b[1].url,a),b[1].libs&&E&&E(b[1].libs))},sa=function(a){A("gc",a)},G=null,ta=function(a){G=a},D=function(a,b,c){if(G){a={t:a,b:b};if(c)for(var d in c)a[d]=c[d];try{G(a)}catch(g){}}};n("mdc",w);n("mdi",ma);n("bnc",y);n("qGC",sa);n("qm",B);n("qd",z);n("lb",F);n("mcf",qa);n("bcf",pa);n("aq",A);
    n("mdd","");n("has",ra);n("trh",ta);n("tev",D);if(h.a("m;/_/scs/abc-static/_/js/k=gapi.gapi.en.q86ihocu0HA.O/d=1/rs=AHpOoo9gC2cqySYcBh8kT9LMyuiwdwIYGQ/m=__features__")){var H=function(a,b){return ua?a||b:b},I=h.a("1"),va=h.a(""),wa=h.a(""),ua=h.a(""),J=window.gapi=H(window.gapi,{}),K=function(a,b){var c=function(){f.dgl(a,b)};I?B(c):(A("gl",c),F("gl"))},xa={},ya=function(a){a=a.split(":");for(var b;(b=a.pop())&&xa[b];);return!b},E=function(a){function b(){for(var c=a.split(":"),d,g=0;d=c[g];++g)xa[d]=1;for(c=0;d=y[c];++c)d=d[1],(g=d.libs)&&!d.l&&d.i&&ya(g)&&
    d.i()}f.dgl(a,b)},L=window.___jsl=H(window.___jsl,{});L.h=H(L.h,"m;/_/scs/abc-static/_/js/k=gapi.gapi.en.q86ihocu0HA.O/d=1/rs=AHpOoo9gC2cqySYcBh8kT9LMyuiwdwIYGQ/m=__features__");L.ms=H(L.ms,"https://apis.google.com");L.m=H(L.m,"");L.l=H(L.l,[]);L.dpo=H(L.dpo,"");I||y.push(["gl",{url:"//ssl.gstatic.com/gb/js/abc/glm_e7bb39a7e1a24581ff4f8d199678b1b9.js"}]);var za="gl",Aa={pu:va,sh:"",si:wa,hl:"ar"};w[za]=Aa;ua?J.load||n("load",K,J):n("load",K,J);n("dgl",K);n("agl",ya);h.o=I};var Ba=h.b("0.1",.001),Ca=0;
    function _mlToken(a,b){try{if(1>Ca){Ca++;var c=a;b=b||{};var d=encodeURIComponent,g=["//www.google.com/gen_204?atyp=i&zx=",(new Date).getTime(),"&jexpid=",d("28834"),"&srcpg=",d("prop=1"),"&jsr=",Math.round(1/Ba),"&ogev=",d("wXOSZfPxAuaekdUPgJ2e4AM"),"&ogf=",f.bv.f,"&ogrp=",d(""),"&ogv=",d("591754533.0"),"&oggv="+d("es_plusone_gc_20231031.0_p2"),"&ogd=",d("com"),"&ogc=",d("LBN"),"&ogl=",d("ar")];b._sn&&(b._sn=
    "og."+b._sn);for(var k in b)g.push("&"),g.push(d(k)),g.push("="),g.push(d(b[k]));g.push("&emsg=");g.push(d(c.name+":"+c.message));var m=g.join("");Ga(m)&&(m=m.substr(0,2E3));var p=m;var l=window.gbar.logger._aem(a,p);la(l)}}catch(t){}}var Ga=function(a){return 2E3<=a.length},Ja=function(a,b){return b};function Ka(a){r=a;n("_itl",Ga,v);n("_aem",Ja,v);n("ml",r,v);a="er";var b={};w[a]=b}h.a("")?Ka(function(a){throw a;}):h.a("1")&&Math.random()<Ba&&Ka(_mlToken);var _E="right",La=h.a(""),Ma=h.a(""),N=function(a,b){var c=a.className;M(a,b)||(a.className+=(""!=c?" ":"")+b)},O=function(a,b){var c=a.className;b=new RegExp("\\s?\\b"+b+"\\b");c&&c.match(b)&&(a.className=c.replace(b,""))},M=function(a,b){b=new RegExp("\\b"+b+"\\b");a=a.className;return!(!a||!a.match(b))},Na=function(a,b){M(a,b)?O(a,b):N(a,b)},Oa=function(a,b){a[b]=function(c){var d=arguments;f.qm(function(){a[b].apply(this,d)})}},Pa=function(a){a=
    [Ma?"":"https://www.gstatic.com","/og/_/js/d=1/k=","og.og.en_US.QyC5j4_7WQo.es5.O","/rt=j/m=",a,"/rs=","AA2YrTvL01Kts_JbAVgbJav3k0k6ByYaNA"];La&&a.push("?host=www.gstatic.com&bust=og.og.en_US.RNyV_MhQ5-U.es5.DU");a=a.join("");C(a)};n("ca",N);n("cr",O);n("cc",M);h.k=N;h.l=O;h.m=M;h.n=Na;h.p=Pa;h.q=Oa;var Qa=["gb_71","gb_155"],Ra;function Sa(a){Ra=a}function Ta(a){var b=Ra&&!a.href.match(/.*\/accounts\/ClearSID[?]/)&&encodeURIComponent(Ra());b&&(a.href=a.href.replace(/([?&]continue=)[^&]*/,"$1"+b))}function Ua(a){window.gApplication&&(a.href=window.gApplication.getTabUrl(a.href))}function Va(a){try{var b=(document.forms[0].q||"").value;b&&(a.href=a.href.replace(/([?&])q=[^&]*|$/,function(c,d){return(d||"&")+"q="+encodeURIComponent(b)}))}catch(c){q(c,"sb","pq")}}
    var Wa=function(){for(var a=[],b,c=0;b=Qa[c];++c)(b=document.getElementById(b))&&a.push(b);return a},Xa=function(){var a=Wa();return 0<a.length?a[0]:null},Ya=function(){return document.getElementById("gb_70")},P={},Q={},Za={},R={},S=void 0,db=function(a,b){try{var c=document.getElementById("gb");N(c,"gbpdjs");T();$a(document.getElementById("gb"))&&N(c,"gbrtl");if(b&&b.getAttribute){var d=b.getAttribute("aria-owns");if(d.length){var g=document.getElementById(d);if(g){var k=b.parentNode;if(S==d)S=void 0,
    O(k,"gbto");else{if(S){var m=document.getElementById(S);if(m&&m.getAttribute){var p=m.getAttribute("aria-owner");if(p.length){var l=document.getElementById(p);l&&l.parentNode&&O(l.parentNode,"gbto")}}}ab(g)&&bb(g);S=d;N(k,"gbto")}}}}B(function(){f.tg(a,b,!0)});cb(a)}catch(t){q(t,"sb","tg")}},eb=function(a){B(function(){f.close(a)})},fb=function(a){B(function(){f.rdd(a)})},$a=function(a){var b,c=document.defaultView;c&&c.getComputedStyle?(a=c.getComputedStyle(a,""))&&(b=a.direction):b=a.currentStyle?
    a.currentStyle.direction:a.style.direction;return"rtl"==b},hb=function(a,b,c){if(a)try{var d=document.getElementById("gbd5");if(d){var g=d.firstChild,k=g.firstChild,m=document.createElement("li");m.className=b+" gbmtc";m.id=c;a.className="gbmt";m.appendChild(a);if(k.hasChildNodes()){c=[["gbkc"],["gbf","gbe","gbn"],["gbkp"],["gbnd"]];d=0;var p=k.childNodes.length;g=!1;for(var l=-1,t,Da=0;t=c[Da];Da++){for(var ba=void 0,Ea=0;ba=t[Ea];Ea++){for(;d<p&&M(k.childNodes[d],ba);)d++;if(ba==b){k.insertBefore(m,
    k.childNodes[d]||null);g=!0;break}}if(g){if(d+1<k.childNodes.length){var Fa=k.childNodes[d+1];M(Fa.firstChild,"gbmh")||gb(Fa,t)||(l=d+1)}else if(0<=d-1){var Ha=k.childNodes[d-1];M(Ha.firstChild,"gbmh")||gb(Ha,t)||(l=d)}break}0<d&&d+1<p&&d++}if(0<=l){var ca=document.createElement("li"),Ia=document.createElement("div");ca.className="gbmtc";Ia.className="gbmt gbmh";ca.appendChild(Ia);k.insertBefore(ca,k.childNodes[l])}f.addHover&&f.addHover(a)}else k.appendChild(m)}}catch(vb){q(vb,"sb","al")}},gb=function(a,
    b){for(var c=b.length,d=0;d<c;d++)if(M(a,b[d]))return!0;return!1},ib=function(a,b,c){hb(a,b,c)},jb=function(a,b){hb(a,"gbe",b)},kb=function(){B(function(){f.pcm&&f.pcm()})},lb=function(){B(function(){f.pca&&f.pca()})},mb=function(a,b,c,d,g,k,m,p,l,t){B(function(){f.paa&&f.paa(a,b,c,d,g,k,m,p,l,t)})},nb=function(a,b){P[a]||(P[a]=[]);P[a].push(b)},ob=function(a,b){Q[a]||(Q[a]=[]);Q[a].push(b)},pb=function(a,b){Za[a]=b},qb=function(a,b){R[a]||(R[a]=[]);R[a].push(b)},cb=function(a){a.preventDefault&&
    a.preventDefault();a.returnValue=!1;a.cancelBubble=!0},rb=null,bb=function(a,b){T();if(a){sb(a,"&#1580;&#1575;&#1585;&#1613; &#1575;&#1604;&#1601;&#1578;&#1581;&hellip;");U(a,!0);b="undefined"!=typeof b?b:1E4;var c=function(){tb(a)};rb=window.setTimeout(c,b)}},ub=function(a){T();a&&(U(a,!1),sb(a,""))},tb=function(a){try{T();var b=a||document.getElementById(S);b&&(sb(b,"&#1607;&#1584;&#1607; &#1575;&#1604;&#1582;&#1583;&#1605;&#1577; &#1594;&#1610;&#1585; &#1605;&#1578;&#1608;&#1601;&#1585;&#1577; &#1601;&#1610; &#1575;&#1604;&#1608;&#1602;&#1578; &#1575;&#1604;&#1581;&#1575;&#1604;&#1610;.%1$s&#1610;&#1615;&#1585;&#1580;&#1609; &#1573;&#1593;&#1575;&#1583;&#1577; &#1575;&#1604;&#1605;&#1581;&#1575;&#1608;&#1604;&#1577; &#1604;&#1575;&#1581;&#1602;&#1611;&#1575;.","%1$s"),U(b,!0))}catch(c){q(c,"sb","sdhe")}},sb=function(a,b,c){if(a&&b){var d=ab(a);if(d){if(c){d.textContent="";b=b.split(c);for(var g=0;c=
    b[g];g++){var k=document.createElement("div");k.innerHTML=c;d.appendChild(k)}}else d.innerHTML=b;U(a,!0)}}},U=function(a,b){(b=void 0!==b?b:!0)?N(a,"gbmsgo"):O(a,"gbmsgo")},ab=function(a){for(var b,c=0;b=a.childNodes[c];c++)if(M(b,"gbmsg"))return b},T=function(){rb&&window.clearTimeout(rb)},wb=function(a){var b="inner"+a;a="offset"+a;return window[b]?window[b]:document.documentElement&&document.documentElement[a]?document.documentElement[a]:0},xb=function(){return!1},yb=function(){return!!S};
    n("so",Xa);n("sos",Wa);n("si",Ya);n("tg",db);n("close",eb);n("rdd",fb);n("addLink",ib);n("addExtraLink",jb);n("pcm",kb);n("pca",lb);n("paa",mb);n("ddld",bb);n("ddrd",ub);n("dderr",tb);n("rtl",$a);n("op",yb);n("bh",P);n("abh",nb);n("dh",Q);n("adh",ob);n("ch",R);n("ach",qb);n("eh",Za);n("aeh",pb);da=h.a("")?Ua:Va;n("qs",da);n("setContinueCb",Sa);n("pc",Ta);n("bsy",xb);h.d=cb;h.j=wb;var zb="base",Ab={};w[zb]=Ab;y.push(["m",{url:"//ssl.gstatic.com/gb/js/sem_5e6825101553e9529a89dc6f94e6d1c6.js"}]);f.sg={c:"1"};n("wg",{rg:{}});var Bb="wg",Cb={tiw:h.c("15000",0),tie:h.c("30000",0)};w[Bb]=Cb;var Db="wm",Eb={thi:h.c("10000",0),thp:h.c("180000",0),tho:h.c("5000",0),tet:h.b("0.5",0)};w[Db]=Eb;if(h.a("1")){var Fb=h.a("");y.push(["gc",{auto:Fb,url:"//ssl.gstatic.com/gb/js/abc/gci_91f30755d6a6b787dcc2a4062e6e9824.js",libs:"googleapis.client:gapi.iframes"}]);var Gb="gc",Hb={version:"gci_91f30755d6a6b787dcc2a4062e6e9824.js",index:"",lang:"ar"};w[Gb]=Hb;var Ib=function(a){window.googleapis&&window.iframes?a&&a():(a&&sa(a),F("gc"))};n("lGC",Ib);h.a("1")&&n("lPWF",Ib)};window.__PVT="";function Jb(){}u=Jb;n("il",u,v);var Kb="il",Lb={};w[Kb]=Lb;var Mb=function(a,b,c,d,g,k,m,p,l,t){B(function(){f.paa(a,b,c,d,g,k,m,p,l,t)})},Nb=function(){B(function(){f.prm()})},Ob=function(a){B(function(){f.spn(a)})},Pb=function(a){B(function(){f.sps(a)})},Qb=function(a){B(function(){f.spp(a)})},Rb={"27":"https://lh3.googleusercontent.com/ogw/default-user=s24","27":"https://lh3.googleusercontent.com/ogw/default-user=s24","27":"https://lh3.googleusercontent.com/ogw/default-user=s24"},Sb=function(a){return(a=Rb[a])||"https://lh3.googleusercontent.com/ogw/default-user=s24"},
    Tb=function(){B(function(){f.spd()})};n("spn",Ob);n("spp",Qb);n("sps",Pb);n("spd",Tb);n("paa",Mb);n("prm",Nb);nb("gbd4",Nb);
    if(h.a("")){var Ub="prf",Vb={d:h.a(""),e:"",sanw:h.a(""),p:"https://lh3.googleusercontent.com/ogw/default-user=s96",cp:"1",xp:h.a("1"),mg:"%1$s (&#1605;&#1601;&#1608;&#1590;)",md:"%1$s (&#1578;&#1604;&#1602;&#1575;&#1574;&#1610;)",mh:"220",s:"1",pp:Sb,ppl:h.a(""),ppa:h.a(""),
    ppm:"&#1589;&#1601;&#1581;&#1577; Google+"};w[Ub]=Vb};var V,Wb,W,Xb,X=0,Yb=function(a,b,c){if(a.indexOf)return a.indexOf(b,c);if(Array.indexOf)return Array.indexOf(a,b,c);for(c=null==c?0:0>c?Math.max(0,a.length+c):c;c<a.length;c++)if(c in a&&a[c]===b)return c;return-1},Y=function(a,b){return-1==Yb(a,X)?(q(Error(X+"_"+b),"up","caa"),!1):!0},$b=function(a,b){Y([1,2],"r")&&(V[a]=V[a]||[],V[a].push(b),2==X&&window.setTimeout(function(){b(Zb(a))},0))},ac=function(a,b,c){if(Y([1],"nap")&&c){for(var d=0;d<c.length;d++)Wb[c[d]]=!0;f.up.spl(a,b,"nap",c)}},bc=
    function(a,b,c){if(Y([1],"aop")&&c){if(W)for(var d in W)W[d]=W[d]&&-1!=Yb(c,d);else for(W={},d=0;d<c.length;d++)W[c[d]]=!0;f.up.spl(a,b,"aop",c)}},cc=function(){try{if(X=2,!Xb){Xb=!0;for(var a in V)for(var b=V[a],c=0;c<b.length;c++)try{b[c](Zb(a))}catch(d){q(d,"up","tp")}}}catch(d){q(d,"up","mtp")}},Zb=function(a){if(Y([2],"ssp")){var b=!Wb[a];W&&(b=b&&!!W[a]);return b}};Xb=!1;V={};Wb={};W=null;X=1;
    var dc=function(a){var b=!1;try{b=a.cookie&&a.cookie.match("PREF")}catch(c){}return!b},ec=function(){try{return!!e.localStorage&&"object"==typeof e.localStorage}catch(a){return!1}},fc=function(a){return a&&a.style&&a.style.behavior&&"undefined"!=typeof a.load},gc=function(a,b,c,d){try{dc(document)||(d||(b="og-up-"+b),ec()?e.localStorage.setItem(b,c):fc(a)&&(a.setAttribute(b,c),a.save(a.id)))}catch(g){g.code!=DOMException.QUOTA_EXCEEDED_ERR&&q(g,"up","spd")}},hc=function(a,b,c){try{if(dc(document))return"";
    c||(b="og-up-"+b);if(ec())return e.localStorage.getItem(b);if(fc(a))return a.load(a.id),a.getAttribute(b)}catch(d){d.code!=DOMException.QUOTA_EXCEEDED_ERR&&q(d,"up","gpd")}return""},ic=function(a,b,c){a.addEventListener?a.addEventListener(b,c,!1):a.attachEvent&&a.attachEvent("on"+b,c)},jc=function(a){for(var b,c=0;b=a[c];c++){var d=f.up;b=b in d&&d[b];if(!b)return!1}return!0},kc=function(a,b){try{if(dc(a))return-1;var c=a.cookie.match(/OGPC=([^;]*)/);if(c&&c[1]){var d=c[1].match(new RegExp("\\b"+
    b+"-([0-9]+):"));if(d&&d[1])return parseInt(d[1],10)}}catch(g){g.code!=DOMException.QUOTA_EXCEEDED_ERR&&q(g,"up","gcc")}return-1};n("up",{r:$b,nap:ac,aop:bc,tp:cc,ssp:Zb,spd:gc,gpd:hc,aeh:ic,aal:jc,gcc:kc});var Z=function(a,b){a[b]=function(c){var d=arguments;f.qm(function(){a[b].apply(this,d)})}};Z(f.up,"sl");Z(f.up,"si");Z(f.up,"spl");Z(f.up,"dpc");Z(f.up,"iic");f.mcf("up",{sp:h.b("0.01",1),tld:"com.lb",prid:"1"});function lc(){function a(){for(var l;(l=k[m++])&&"m"!=l[0]&&!l[1].auto;);l&&(D(2,l[0]),l[1].url&&C(l[1].url,l[0]),l[1].libs&&E&&E(l[1].libs));m<k.length&&setTimeout(a,0)}function b(){0<g--?setTimeout(b,0):a()}var c=h.a("1"),d=h.a(""),g=3,k=y,m=0,p=window.gbarOnReady;if(p)try{p()}catch(l){q(l,"ml","or")}d?n("ldb",a):c?ea(window,"load",b):b()}n("rdl",lc);}catch(e){window.gbar&&gbar.logger&&gbar.logger.ml(e,{"_sn":"cfg.init"});}})();
    (function(){try{var b=window.gbar.i.i;var c=window.gbar;var f=function(d){try{var a=document.getElementById("gbom");a&&d.appendChild(a.cloneNode(!0))}catch(e){b(e,"omas","aomc")}};c.aomc=f;}catch(e){window.gbar&&gbar.logger&&gbar.logger.ml(e,{"_sn":"cfg.init"});}})();
    (function(){try{var a=window.gbar;a.mcf("pm",{p:""});}catch(e){window.gbar&&gbar.logger&&gbar.logger.ml(e,{"_sn":"cfg.init"});}})();
    (function(){try{var a=window.gbar;a.mcf("mm",{s:"1"});}catch(e){window.gbar&&gbar.logger&&gbar.logger.ml(e,{"_sn":"cfg.init"});}})();
    (function(){try{var d=window.gbar.i.i;var e=window.gbar;var f=e.i;var g=f.c("1",0),h=/\bgbmt\b/,k=function(a){try{var b=document.getElementById("gb_"+g),c=document.getElementById("gb_"+a);b&&f.l(b,h.test(b.className)?"gbm0l":"gbz0l");c&&f.k(c,h.test(c.className)?"gbm0l":"gbz0l")}catch(l){d(l,"sj","ssp")}g=a},m=e.qs,n=function(a){var b=a.href;var c=window.location.href.match(/.*?:\/\/[^\/]*/)[0];c=new RegExp("^"+c+"/search\\?");(b=c.test(b))&&!/(^|\\?|&)ei=/.test(a.href)&&(b=window.google)&&b.kEXPI&&(a.href+="&ei="+b.kEI)},p=function(a){m(a);
    n(a)},q=function(){if(window.google&&window.google.sn){var a=/.*hp$/;return a.test(window.google.sn)?"":"1"}return"-1"};e.rp=q;e.slp=k;e.qs=p;e.qsi=n;}catch(e){window.gbar&&gbar.logger&&gbar.logger.ml(e,{"_sn":"cfg.init"});}})();
    (function(){try{/*
    
     Copyright The Closure Library Authors.
     SPDX-License-Identifier: Apache-2.0
    */
    var a=this||self;var b=window.gbar;var c=b.i;var d=c.a,e=c.c,f={cty:"LBN",cv:"591754533",dbg:d(""),ecv:"0",ei:e("wXOSZfPxAuaekdUPgJ2e4AM"),ele:d("1"),esr:e("0.1"),evts:["mousedown","touchstart","touchmove","wheel","keydown"],gbl:"es_plusone_gc_20231031.0_p2",hd:"com",hl:"ar",irp:d(""),pid:e("1"),
    snid:e("28834"),to:e("300000"),u:e(""),vf:".66."},g="bndcfg",h=f,k=g.split("."),l=a;k[0]in l||"undefined"==typeof l.execScript||l.execScript("var "+k[0]);for(var m;k.length&&(m=k.shift());)k.length||void 0===h?l=l[m]&&l[m]!==Object.prototype[m]?l[m]:l[m]={}:l[m]=h;}catch(e){window.gbar&&gbar.logger&&gbar.logger.ml(e,{"_sn":"cfg.init"});}})();
    (function(){try{window.gbar.rdl();}catch(e){window.gbar&&gbar.logger&&gbar.logger.ml(e,{"_sn":"cfg.init"});}})();
    </script></head><body bgcolor="#fff"><script nonce="M2mhXcT2weLVc33PCU9lFg">(function(){var src='/images/nav_logo229.png';var iesg=false;document.body.onload = function(){window.n && window.n();if (document.images){new Image().src=src;}
    if (!iesg){document.f&&document.f.q.focus();document.gbqf&&document.gbqf.q.focus();}
    }
    })();</script><div id="mngb"><div id=gb dir=rtl class="gbrtl"><script nonce='M2mhXcT2weLVc33PCU9lFg'>window.gbar&&gbar.eli&&gbar.eli()</script><div id=gbw><div id=gbz><span class=gbtcb></span><ol id=gbzc class=gbtc><li class=gbt><a class="gbzt gbz0l gbp1" id=gb_1 href="https://www.google.com.lb/webhp?tab=ww"><span class=gbtb2></span><span class=gbts>&#1576;&#1581;&#1579;</span></a></li><li class=gbt><a class=gbzt id=gb_2 href="https://www.google.com/imghp?hl=ar&tab=wi"><span class=gbtb2></span><span class=gbts>&#1589;&#1608;&#1585;</span></a></li><li class=gbt><a class=gbzt id=gb_8 href="http://maps.google.com.lb/maps?hl=ar&tab=wl"><span class=gbtb2></span><span class=gbts>&#1582;&#1585;&#1575;&#1574;&#1591; Google</span></a></li><li class=gbt><a class=gbzt id=gb_78 href="https://play.google.com/?hl=ar&tab=w8"><span class=gbtb2></span><span class=gbts>Play</span></a></li><li class=gbt><a class=gbzt id=gb_36 href="https://www.youtube.com/?tab=w1"><span class=gbtb2></span><span class=gbts>YouTube</span></a></li><li class=gbt><a class=gbzt id=gb_426 href="https://news.google.com/?tab=wn"><span class=gbtb2></span><span class=gbts>&#1575;&#1604;&#1571;&#1582;&#1576;&#1575;&#1585;</span></a></li><li class=gbt><a class=gbzt id=gb_23 href="https://mail.google.com/mail/?tab=wm"><span class=gbtb2></span><span class=gbts>Gmail</span></a></li><li class=gbt><a class=gbzt id=gb_49 href="https://drive.google.com/?tab=wo"><span class=gbtb2></span><span class=gbts>Drive</span></a></li><li class=gbt><a class=gbgt id=gbztm href="https://www.google.com.lb/intl/ar/about/products?tab=wh"  aria-haspopup=true aria-owns=gbd><span class=gbtb2></span><span id=gbztms class="gbts gbtsa"><span id=gbztms1>&#1575;&#1604;&#1605;&#1586;&#1610;&#1583;</span><span class=gbma></span></span></a><script nonce='M2mhXcT2weLVc33PCU9lFg'>document.getElementById('gbztm').addEventListener('click', function clickHandler() { gbar.tg(event,this); });</script><div class=gbm id=gbd aria-owner=gbztm><div id=gbmmb class="gbmc gbsb gbsbis"><ol id=gbmm class="gbmcc gbsbic"><li class=gbmtc><a class=gbmt id=gb_24 href="https://calendar.google.com/calendar?tab=wc">&#1578;&#1602;&#1608;&#1610;&#1605;</a></li><li class=gbmtc><a class=gbmt id=gb_51 href="https://translate.google.com.lb/?hl=ar&tab=wT">&#1578;&#1585;&#1580;&#1605;&#1577;</a></li><li class=gbmtc><a class=gbmt id=gb_10 href="https://books.google.com.lb/?hl=ar&tab=wp">&#1575;&#1604;&#1603;&#1578;&#1576;</a></li><li class=gbmtc><a class=gbmt id=gb_6 href="https://www.google.com.lb/shopping?hl=ar&source=og&tab=wf">&#1575;&#1604;&#1578;&#1587;&#1608;&#1617;&#1602;</a></li><li class=gbmtc><a class=gbmt id=gb_30 href="http://www.blogger.com/?tab=wj">Blogger</a></li><li class=gbmtc><a class=gbmt id=gb_27 href="https://www.google.com/finance?tab=we">&#1575;&#1604;&#1571;&#1605;&#1608;&#1575;&#1604;</a></li><li class=gbmtc><a class=gbmt id=gb_31 href="https://photos.google.com/?tab=wq&pageId=none">&#1575;&#1604;&#1589;&#1608;&#1585;</a></li><li class=gbmtc><a class=gbmt id=gb_25 href="https://docs.google.com/document/?usp=docs_alc">&#1605;&#1587;&#1578;&#1606;&#1583;&#1575;&#1578;</a></li><li class=gbmtc><div class="gbmt gbmh"></div></li><li class=gbmtc><a  href="https://www.google.com.lb/intl/ar/about/products?tab=wh" class=gbmt>&#1575;&#1604;&#1605;&#1586;&#1610;&#1583; &#1571;&#1610;&#1590;&#1611;&#1575; &raquo;</a><script nonce='M2mhXcT2weLVc33PCU9lFg'>document.querySelector('li > a.gbmt').addEventListener('click', function clickHandler() { gbar.logger.il(1,{t:66});; });</script></li></ol><div class=gbsbt></div><div class=gbsbb></div></div></div></li></ol></div><div id=gbg><h2 class=gbxx>Account Options</h2><span class=gbtcb></span><ol class=gbtc><li class=gbt><a target=_top href="https://accounts.google.com/ServiceLogin?hl=ar&passive=true&continue=http://www.google.com/&ec=GAZAAQ" onclick="gbar.logger.il(9,{l:'i'})" id=gb_70 class=gbgt><span class=gbtb2></span><span id=gbgs4 class=gbts><span id=gbi4s1>&#1578;&#1587;&#1580;&#1610;&#1604; &#1575;&#1604;&#1583;&#1582;&#1608;&#1604;</span></span></a></li><li class="gbt gbtb"><span class=gbts></span></li><li class=gbt><a class=gbgt id=gbg5 href="http://www.google.com.lb/preferences?hl=ar" title="&#1582;&#1610;&#1575;&#1585;&#1575;&#1578;" aria-haspopup=true aria-owns=gbd5><span class=gbtb2></span><span id=gbgs5 class=gbts><span id=gbi5></span></span></a><script nonce='M2mhXcT2weLVc33PCU9lFg'>document.getElementById('gbg5').addEventListener('click', function clickHandler() { gbar.tg(event,this); });</script><div class=gbm id=gbd5 aria-owner=gbg5><div class=gbmc><ol id=gbom class=gbmcc><li class="gbkc gbmtc"><a  class=gbmt href="/preferences?hl=ar">&#1573;&#1593;&#1583;&#1575;&#1583;&#1575;&#1578; &#1575;&#1604;&#1576;&#1581;&#1579;</a></li><li class=gbmtc><div class="gbmt gbmh"></div></li><li class="gbkp gbmtc"><a class=gbmt href="http://www.google.com.lb/history/optout?hl=ar">&#1587;&#1616;&#1580;&#1604; &#1576;&#1581;&#1579; &#1575;&#1604;&#1608;&#1610;&#1576;</a></li></ol></div></div></li></ol></div></div><div id=gbx3></div><div id=gbx4></div><script nonce='M2mhXcT2weLVc33PCU9lFg'>window.gbar&&gbar.elp&&gbar.elp()</script></div></div><center><br clear="all" id="lgpd"><div id="lga"><a href="/search?sca_esv=594855337&amp;ie=UTF-8&amp;q=%D8%B9%D9%8A%D8%AF+%D8%B1%D8%A3%D8%B3+%D8%A7%D9%84%D8%B3%D9%86%D8%A9&amp;oi=ddle&amp;ct=306729682&amp;hl=ar&amp;si=AKbGX_rO4P19IF_yO85wYpkEaz-W_oZWd5JUOOVnUVftf2aeoS55Tv22Q6M-pVdLFOW9CearwZX8VRBuWnS08X2VR1FCpefGOmc6Hw0wKNJSlOR-2EZtdQVuePvLwQdxG4AsdEPjrngQnZnRmf-KYU62iFe4IRvNSS03wRIJZk3N7zg__1q7ocBbAIJoMs5QlOnVsMRTxMbG&amp;sa=X&amp;ved=0ahUKEwj_5pD23ruDAxWMRqQEHX-ZDUAQPQgD"><img alt="&#1593;&#1610;&#1583; &#1585;&#1571;&#1587; &#1575;&#1604;&#1587;&#1606;&#1577; 2024" border="0" height="200" src="/logos/doodles/2024/new-years-day-2024-6753651837110174-law.gif" title="&#1593;&#1610;&#1583; &#1585;&#1571;&#1587; &#1575;&#1604;&#1587;&#1606;&#1577; 2024" width="500" id="hplogo"><br></a><br></div><form action="/search" name="f"><table cellpadding="0" cellspacing="0"><tr valign="top"><td width="25%">&nbsp;</td><td align="center" nowrap=""><input name="ie" value="ISO-8859-1" type="hidden"><input value="ar-LB" name="hl" type="hidden"><input name="source" type="hidden" value="hp"><input name="biw" type="hidden"><input name="bih" type="hidden"><div class="ds" style="height:32px;margin:4px 0"><div style="position:relative;zoom:1"><input class="lst Ucigb" style="margin:0;padding:5px 6px 0 8px;vertical-align:top;color:#000;padding-left:38px" autocomplete="off" value="" title="&#1576;&#1581;&#1579; Google" maxlength="2048" name="q" size="57"><img src="/textinputassistant/tia.png" style="position:absolute;cursor:pointer;left:5px;top:4px;z-index:300" data-script-url="/textinputassistant/13/ar_tia.js" id="tsuid_1" alt="" height="23" width="27"><script nonce="M2mhXcT2weLVc33PCU9lFg">(function(){var id='tsuid_1';document.getElementById(id).onclick = function(){var s = document.createElement('script');s.src = this.getAttribute('data-script-url');(document.getElementById('xjsc')||document.body).appendChild(s);};})();</script></div></div><br style="line-height:0"><span class="ds"><span class="lsbb"><input class="lsb" value="&#1576;&#1581;&#1579; Google" name="btnG" type="submit"></span></span><span class="ds"><span class="lsbb"><input class="lsb" id="tsuid_2" value="&#1590;&#1585;&#1576;&#1577; &#1581;&#1592;" name="btnI" type="submit"><script nonce="M2mhXcT2weLVc33PCU9lFg">(function(){var id='tsuid_2';document.getElementById(id).onclick = function(){if (this.form.q.value){this.checked = 1;if (this.form.iflsig)this.form.iflsig.disabled = false;}
    else top.location='/doodles/';};})();</script><input value="AO6bgOgAAAAAZZKB0RN9_RgIprT99RcHL58KX5pWw9R9" name="iflsig" type="hidden"></span></span></td><td class="fl sblc" align="right" nowrap="" width="25%"><a href="/advanced_search?hl=ar-LB&amp;authuser=0">&#1576;&#1581;&#1579; &#1605;&#1578;&#1602;&#1583;&#1605;</a></td></tr></table><input id="gbv" name="gbv" type="hidden" value="1"><script nonce="M2mhXcT2weLVc33PCU9lFg">(function(){var a,b="1";if(document&&document.getElementById)if("undefined"!=typeof XMLHttpRequest)b="2";else if("undefined"!=typeof ActiveXObject){var c,d,e=["MSXML2.XMLHTTP.6.0","MSXML2.XMLHTTP.3.0","MSXML2.XMLHTTP","Microsoft.XMLHTTP"];for(c=0;d=e[c++];)try{new ActiveXObject(d),b="2"}catch(h){}}a=b;if("2"==a&&-1==location.search.indexOf("&gbv=2")){var f=google.gbvu,g=document.getElementById("gbv");g&&(g.value=a);f&&window.setTimeout(function(){location.href=f},0)};}).call(this);</script></form><div id="gac_scont"></div><div style="font-size:83%;min-height:3.5em"><br><div id="gws-output-pages-elements-homepage_additional_languages__als"><style>#gws-output-pages-elements-homepage_additional_languages__als{font-size:small;margin-bottom:24px}#SIvCob{color:#3c4043;display:inline-block;line-height:28px;}#SIvCob a{padding:0 3px;}.H6sW5{display:inline-block;margin:0 2px;white-space:nowrap}.z4hgWe{display:inline-block;margin:0 2px}</style><div id="SIvCob">&#1605;&#1581;&#1585;&#1617;&#1603; &#1576;&#1581;&#1579; Google &#1605;&#1578;&#1608;&#1601;&#1617;&#1585; &#1576;&#1575;&#1604;&#1604;&#1594;&#1577;:  <a dir="ltr" href="http://www.google.com/setprefs?sig=0_quB37iMq6-oQ2Y9hc_OcGQiT9bk%3D&amp;hl=en&amp;source=homepage&amp;sa=X&amp;ved=0ahUKEwj_5pD23ruDAxWMRqQEHX-ZDUAQ2ZgBCAU">English</a>    <a dir="ltr" href="http://www.google.com/setprefs?sig=0_quB37iMq6-oQ2Y9hc_OcGQiT9bk%3D&amp;hl=fr&amp;source=homepage&amp;sa=X&amp;ved=0ahUKEwj_5pD23ruDAxWMRqQEHX-ZDUAQ2ZgBCAY">Français</a>    <a dir="ltr" href="http://www.google.com/setprefs?sig=0_quB37iMq6-oQ2Y9hc_OcGQiT9bk%3D&amp;hl=hy&amp;source=homepage&amp;sa=X&amp;ved=0ahUKEwj_5pD23ruDAxWMRqQEHX-ZDUAQ2ZgBCAc">&#1392;&#1377;&#1397;&#1381;&#1408;&#1381;&#1398;</a>  </div></div></div><span id="footer"><div style="font-size:10pt"><div style="margin:19px auto;text-align:center" id="WqQANb"><a href="/intl/ar/ads/">&#1575;&#1604;&#1573;&#1593;&#1604;&#1575;&#1606;&#1575;&#1578;</a><a href="http://www.google.com/intl/ar/services/">&#1581;&#1604;&#1608;&#1604; &#1575;&#1604;&#1588;&#1585;&#1603;&#1575;&#1578;</a><a href="/intl/ar/about.html">&#1603;&#1604; &#1605;&#1575; &#1578;&#1581;&#1576; &#1605;&#1593;&#1585;&#1601;&#1578;&#1607; &#1593;&#1606; Google &#1607;&#1606;&#1575;</a><a dir="ltr" href="http://www.google.com/setprefdomain?prefdom=LB&amp;prev=http://www.google.com.lb/&amp;sig=K_1M5rgo4a9b0Vq1ohGsfuKQgWUHE%3D">Google.com.lb</a></div></div><p style="font-size:8pt;color:#70757a">&copy; 2024 - <a href="/intl/ar/policies/privacy/">&#1575;&#1604;&#1582;&#1589;&#1608;&#1589;&#1610;&#1577;</a> - <a href="/intl/ar/policies/terms/">&#1575;&#1604;&#1576;&#1606;&#1608;&#1583;</a></p></span></center><script nonce="M2mhXcT2weLVc33PCU9lFg">(function(){window.google.cdo={height:757,width:1440};(function(){var a=window.innerWidth,b=window.innerHeight;if(!a||!b){var c=window.document,d="CSS1Compat"==c.compatMode?c.documentElement:c.body;a=d.clientWidth;b=d.clientHeight}
    if(a&&b&&(a!=google.cdo.width||b!=google.cdo.height)){var e=google,f=e.log,g="/client_204?&atyp=i&biw="+a+"&bih="+b+"&ei="+google.kEI,h="",k=[],l=void 0!==window.google&&void 0!==window.google.kOPI&&0!==window.google.kOPI?window.google.kOPI:null;null!=l&&k.push(["opi",l.toString()]);for(var m=0;m<k.length;m++){if(0===m||0<m)h+="&";h+=k[m][0]+"="+k[m][1]}f.call(e,"","",g+h)};}).call(this);})();</script> <script nonce="M2mhXcT2weLVc33PCU9lFg">(function(){google.xjs={ck:'xjs.hp.vKnqOVkWTM4.R.X.O',combam:'AAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAA4AAACEAAAAAAAAACAkABAdAQAwAIAXA',cs:'ACT90oENYN3ccyuAPf4I1vaUYRNl4ZXiGw',cssam:'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACEAAAAAAAAACAkABA',cssopt:false,csss:'ACT90oEYd7gcM5-KdN3_6tSFOTuXSjmvgw',excm:[],sepam:false,sepcss:false};})();</script>     <script nonce="M2mhXcT2weLVc33PCU9lFg">(function(){var u='/xjs/_/js/k\x3dxjs.hp.en.6YapfFsyys0.O/am\x3dAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAA4AAACEAAAAAAAAACAkABAdAQAwAIAXA/d\x3d1/ed\x3d1/rs\x3dACT90oFf6BZFVwTHos2GVqtaq3SmeyLl5Q/m\x3dsb_he,d,cEt90b,SNUn3,qddgKe,sTsDMc,dtl0hd,eHDfl';var amd=0;
    var e=this||self,f=function(a){return a};var g;var h=function(a){this.g=a};h.prototype.toString=function(){return this.g+""};var k={};var l=function(){var a=document;var b="SCRIPT";"application/xhtml+xml"===a.contentType&&(b=b.toLowerCase());return a.createElement(b)};
    function m(a,b){a.src=b instanceof h&&b.constructor===h?b.g:"type_error:TrustedResourceUrl";var c,d;(c=(b=null==(d=(c=(a.ownerDocument&&a.ownerDocument.defaultView||window).document).querySelector)?void 0:d.call(c,"script[nonce]"))?b.nonce||b.getAttribute("nonce")||"":"")&&a.setAttribute("nonce",c)};function n(a){a=null===a?"null":void 0===a?"undefined":a;if(void 0===g){var b=null;var c=e.trustedTypes;if(c&&c.createPolicy){try{b=c.createPolicy("goog#html",{createHTML:f,createScript:f,createScriptURL:f})}catch(d){e.console&&e.console.error(d.message)}g=b}else g=b}a=(b=g)?b.createScriptURL(a):a;return new h(a,k)};void 0===google.ps&&(google.ps=[]);function p(){var a=u,b=function(){};google.lx=google.stvsc?b:function(){q(a);google.lx=b};google.bx||google.lx()}function r(a,b){b&&m(a,n(b));var c=a.onload;a.onload=function(d){c&&c(d);google.ps=google.ps.filter(function(t){return a!==t})};google.ps.push(a);document.body.appendChild(a)}google.as=r;function q(a){google.timers&&google.timers.load&&google.tick&&google.tick("load","xjsls");var b=l();b.onerror=function(){google.ple=1};b.onload=function(){google.ple=0};google.xjsus=void 0;r(b,a);google.aple=-1;google.psa=!0};google.xjsu=u;e._F_jsUrl=u;setTimeout(function(){0<amd?google.caft(function(){return p()},amd):p()},0);})();window._ = window._ || {};window._DumpException = _._DumpException = function(e){throw e;};window._s = window._s || {};_s._DumpException = _._DumpException;window._qs = window._qs || {};_qs._DumpException = _._DumpException;(function(){var t=[1,0,0,0,0,8192,0,8388654,134217744,33554432,591872,72976,469762752,1];window._F_toggles = window._xjs_toggles = t;})();function _F_installCss(c){}
    (function(){google.jl={blt:'none',chnk:0,dw:false,dwu:true,emtn:0,end:0,ico:false,ikb:0,ine:false,injs:'none',injt:0,injth:0,injv2:false,lls:'default',pdt:0,rep:0,snet:true,strt:0,ubm:false,uwp:true};})();(function(){var pmc='{\x22d\x22:{},\x22sb_he\x22:{\x22agen\x22:false,\x22cgen\x22:false,\x22client\x22:\x22heirloom-hp\x22,\x22dh\x22:true,\x22ds\x22:\x22\x22,\x22fl\x22:true,\x22host\x22:\x22google.com\x22,\x22jsonp\x22:true,\x22msgs\x22:{\x22cibl\x22:\x22\\u0645\\u062d\\u0648 \\u0627\\u0644\\u0628\\u062d\\u062b\x22,\x22dym\x22:\x22\\u0647\\u0644 \\u062a\\u0642\\u0635\\u062f :\x22,\x22lcky\x22:\x22\\u0636\\u0631\\u0628\\u0629 \\u062d\\u0638\x22,\x22lml\x22:\x22\\u0645\\u0632\\u064a\\u062f \\u0645\\u0646 \\u0627\\u0644\\u0645\\u0639\\u0644\\u0648\\u0645\\u0627\\u062a\x22,\x22psrc\x22:\x22\\u062a\\u0645\\u062a \\u0625\\u0632\\u0627\\u0644\\u0629 \\u0647\\u0630\\u0627 \\u0627\\u0644\\u0628\\u062d\\u062b \\u0645\\u0646 \\u003Ca href\x3d\\\x22/history\\\x22\\u003E\\u0633\\u0650\\u062c\\u0644 \\u0627\\u0644\\u0628\\u062d\\u062b\\u003C/a\\u003E.\x22,\x22psrl\x22:\x22\\u0625\\u0632\\u0627\\u0644\\u0629\x22,\x22sbit\x22:\x22\\u0627\\u0644\\u0628\\u062d\\u062b \\u0628\\u062d\\u0633\\u0628 \\u0627\\u0644\\u0635\\u0648\\u0631\x22,\x22srch\x22:\x22\\u0628\\u062d\\u062b Google\\u200f\x22},\x22ovr\x22:{},\x22pq\x22:\x22\x22,\x22rfs\x22:[],\x22sbas\x22:\x220 3px 8px 0 rgba(0,0,0,0.2),0 0 0 1px rgba(0,0,0,0.08)\x22,\x22stok\x22:\x222djt8-UxntokmIvZ79GO-CwDAKc\x22}}';google.pmc=JSON.parse(pmc);})();(function(){var b=function(a){var c=0;return function(){return c<a.length?{done:!1,value:a[c++]}:{done:!0}}};
    var e=this||self;var g,h;a:{for(var k=["CLOSURE_FLAGS"],l=e,n=0;n<k.length;n++)if(l=l[k[n]],null==l){h=null;break a}h=l}var p=h&&h[610401301];g=null!=p?p:!1;var q,r=e.navigator;q=r?r.userAgentData||null:null;function t(a){return g?q?q.brands.some(function(c){return(c=c.brand)&&-1!=c.indexOf(a)}):!1:!1}function u(a){var c;a:{if(c=e.navigator)if(c=c.userAgent)break a;c=""}return-1!=c.indexOf(a)};function v(){return g?!!q&&0<q.brands.length:!1}function w(){return u("Safari")&&!(x()||(v()?0:u("Coast"))||(v()?0:u("Opera"))||(v()?0:u("Edge"))||(v()?t("Microsoft Edge"):u("Edg/"))||(v()?t("Opera"):u("OPR"))||u("Firefox")||u("FxiOS")||u("Silk")||u("Android"))}function x(){return v()?t("Chromium"):(u("Chrome")||u("CriOS"))&&!(v()?0:u("Edge"))||u("Silk")}function y(){return u("Android")&&!(x()||u("Firefox")||u("FxiOS")||(v()?0:u("Opera"))||u("Silk"))};var z=v()?!1:u("Trident")||u("MSIE");y();x();w();Object.freeze(new function(){});Object.freeze(new function(){});var A=!z&&!w(),D=function(a){if(/-[a-z]/.test("ved"))return null;if(A&&a.dataset){if(y()&&!("ved"in a.dataset))return null;a=a.dataset.ved;return void 0===a?null:a}return a.getAttribute("data-"+"ved".replace(/([A-Z])/g,"-$1").toLowerCase())};var E=[],F=null;function G(a){a=a.target;var c=performance.now(),f=[],H=f.concat,d=E;if(!(d instanceof Array)){var m="undefined"!=typeof Symbol&&Symbol.iterator&&d[Symbol.iterator];if(m)d=m.call(d);else if("number"==typeof d.length)d={next:b(d)};else throw Error("a`"+String(d));for(var B=[];!(m=d.next()).done;)B.push(m.value);d=B}E=H.call(f,d,[c]);if(a&&a instanceof HTMLElement)if(a===F){if(c=4<=E.length)c=5>(E[E.length-1]-E[E.length-4])/1E3;if(c){c=google.getEI(a);a.hasAttribute("data-ved")?f=a?D(a)||"":"":f=(f=
    a.closest("[data-ved]"))?D(f)||"":"";f=f||"";if(a.hasAttribute("jsname"))a=a.getAttribute("jsname");else{var C;a=null==(C=a.closest("[jsname]"))?void 0:C.getAttribute("jsname")}google.log("rcm","&ei="+c+"&ved="+f+"&jsname="+(a||""))}}else F=a,E=[c]}window.document.addEventListener("DOMContentLoaded",function(){document.body.addEventListener("click",G)});}).call(this);</script></body></html>


### 1.1 Advanced Techniques

Web reconnaissance extends beyond mere webpage retrieval. With `reqwest`, we can delve into advanced techniques such as handling cookies, managing user-agents, and employing proxies for enhanced anonymity. Let's explore how these features can be leveraged to craft a more sophisticated and stealthy web reconnaissance tool in Rust.

#### 1.1.1 Managing Cookies for Persistent Sessions

Cookies play a crucial role in web sessions, and their strategic management is essential for maintaining persistent connections during reconnaissance. In Rust, Reqwest provides robust support for handling cookies. The following example demonstrates how to utilize Reqwest's cookie jar for managing and maintaining cookies across multiple requests:

```rust
use reqwest;

async fn browse_with_cookies(url: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()?;

    let response = client.get(url).send().await?;
    let cookies = response.cookies();

    let new_response = client.get("http://www.google.com/another-page").send().await?;

    println!("{}", new_response
        .text()
        .await?);

    Ok(())
}

browse_with_cookies("http://www.google.com").await.unwrap();
```

In this example, we create a `Reqwest` client with a cookie jar, make a request to a website, store the received cookies, and later use these cookies in a subsequent request. This allows for the maintenance of a persistent session across multiple interactions.



```Rust
async fn browse_with_cookies(url: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()?;

    let response = client.get(url).send().await?;
    let cookies = response.cookies();

    let new_response = client.get("http://www.google.com/another-page").send().await?;

    println!("{}", new_response
        .text()
        .await?);

    Ok(())
}


browse_with_cookies("http://www.google.com").await.unwrap();
```

    <!DOCTYPE html>
    <html lang=en>
      <meta charset=utf-8>
      <meta name=viewport content="initial-scale=1, minimum-scale=1, width=device-width">
      <title>Error 404 (Not Found)!!1</title>
      <style>
        *{margin:0;padding:0}html,code{font:15px/22px arial,sans-serif}html{background:#fff;color:#222;padding:15px}body{margin:7% auto 0;max-width:390px;min-height:180px;padding:30px 0 15px}* > body{background:url(//www.google.com/images/errors/robot.png) 100% 5px no-repeat;padding-right:205px}p{margin:11px 0 22px;overflow:hidden}ins{color:#777;text-decoration:none}a img{border:0}@media screen and (max-width:772px){body{background:none;margin-top:0;max-width:none;padding-right:0}}#logo{background:url(//www.google.com/images/branding/googlelogo/1x/googlelogo_color_150x54dp.png) no-repeat;margin-left:-5px}@media only screen and (min-resolution:192dpi){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat 0% 0%/100% 100%;-moz-border-image:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) 0}}@media only screen and (-webkit-min-device-pixel-ratio:2){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat;-webkit-background-size:100% 100%}}#logo{display:inline-block;height:54px;width:150px}
      </style>
      <a href=//www.google.com/><span id=logo aria-label=Google></span></a>
      <p><b>404.</b> <ins>That’s an error.</ins>
      <p>The requested URL <code>/another-page</code> was not found on this server.  <ins>That’s all we know.</ins>
    


#### 1.1.2 Crafting Stealthy Requests with User-Agents

User-agents convey information about the client's browser and system to the server. Crafting stealthy requests involves manipulating the user-agent string to mimic various browsers or devices. In Rust, Reqwest facilitates this through its header manipulation capabilities. The following example illustrates how to set a custom user-agent header in a Reqwest request:

```rust
use reqwest;

async fn browse_with_custom_user_agent(url: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
        .build()?;

    let response = client.get(url).send().await?;

    println!("{}", response.text().await?);

    Ok(())
}

fn main() {
    browse_with_custom_user_agent("http://www.google.com/invalid").await.unwrap();
}
```

In this example, we create a Reqwest client with a custom user-agent header, making the request appear as if it originates from a specific browser and platform. This manipulation enhances stealth and reduces the likelihood of detection.

```sh

+------------------------+
|                        |
|  +------------------+  |
|  |   Manipulate     |  |
|  |   User-Agent     |  |
|  +------------------+  |
|          |             |
|          V             |
|   +--------------+     |
|   |  Request     |     |
|   |  (Custom     |     |
|   |  User-Agent) |     |
|   +--------------+     |
|          |             |
|          V             |
|   +--------------+     |
|   |  HTTP        |     |
|   |  Request     |     |
|   |  Sent        |     |
|   +--------------+     |
|          |             |
|          V             |
|   +--------------+     |
|   |  Server      |     |
|   |  Response    |     |
|   +--------------+     |
|          |             |
|          V             |
|   +--------------+     |
|   |  Print       |     |
|   |  Response    |     |
|   +--------------+     |
|                        |
+------------------------+
```


```Rust
use reqwest;

async fn browse_with_custom_user_agent(url: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
        .build()?;

    let response = client.get(url).send().await?;

    println!("{}", response.text().await?);

    Ok(())
}


browse_with_custom_user_agent("http://www.google.com/invalid").await.unwrap();
```

    <!DOCTYPE html>
    <html lang=en>
      <meta charset=utf-8>
      <meta name=viewport content="initial-scale=1, minimum-scale=1, width=device-width">
      <title>Error 404 (Not Found)!!1</title>
      <style>
        *{margin:0;padding:0}html,code{font:15px/22px arial,sans-serif}html{background:#fff;color:#222;padding:15px}body{margin:7% auto 0;max-width:390px;min-height:180px;padding:30px 0 15px}* > body{background:url(//www.google.com/images/errors/robot.png) 100% 5px no-repeat;padding-right:205px}p{margin:11px 0 22px;overflow:hidden}ins{color:#777;text-decoration:none}a img{border:0}@media screen and (max-width:772px){body{background:none;margin-top:0;max-width:none;padding-right:0}}#logo{background:url(//www.google.com/images/branding/googlelogo/1x/googlelogo_color_150x54dp.png) no-repeat;margin-left:-5px}@media only screen and (min-resolution:192dpi){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat 0% 0%/100% 100%;-moz-border-image:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) 0}}@media only screen and (-webkit-min-device-pixel-ratio:2){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat;-webkit-background-size:100% 100%}}#logo{display:inline-block;height:54px;width:150px}
      </style>
      <a href=//www.google.com/><span id=logo aria-label=Google></span></a>
      <p><b>404.</b> <ins>That’s an error.</ins>
      <p>The requested URL <code>/invalid</code> was not found on this server.  <ins>That’s all we know.</ins>
    


#### 1.1.3 Leveraging Proxies with Reqwest

Anonymity is a cornerstone of effective web reconnaissance. Reqwest provides support for proxy configurations, allowing us to route requests through different IP addresses to further obfuscate our origin. The following example demonstrates how to configure Reqwest to use a proxy for web requests:

```rust
use reqwest;

async fn browse_with_proxy(url: &str, proxy: reqwest::Proxy) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::builder()
        .build()?;

    let response = client.get(url).send().await?;

    println!("{}", response.text().await?);

    Ok(())
}

fn main() {
    let proxy = reqwest::Proxy::all("socks5://192.168.1.1:9000")?;
    browse_with_proxy("https://www.google.com/invalid", proxy).await.unwrap();
}
```

In this example, we configure Reqwest to use a proxy, directing the requests through the specified proxy URL. This enhances anonymity by masking the original source IP address.

```sh
+-------------------------+
|   Proxies and Reqwest   |
|    for Web Anonymity    |
+-------------------------+
             |
             V
+-------------+-----------+
| Configure Proxy         |
|socks5://192.168.1.1:9000|
+-------------+-----------+
             |
             V
+------------------------+
|   Reqwest Client       |
|   Configure Proxy      |
|URL: socks5://192.168...|
+------------------------+
             |
             V
+------------------------+
| Make Request through   |
|   Configured Proxy     |
+------------------------+
             |
             V
+------------------------+
| Get Response via Proxy |
|  (Hidden Origin)       |
+------------------------+
             |
             V
+------------------------+
|    Print Response      |
+------------------------+

```


```Rust
use reqwest;

async fn browse_with_proxy(url: &str, proxy: reqwest::Proxy) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::builder()
        .build()?;

    let response = client.get(url).send().await?;

    println!("{}", response.text().await?);

    Ok(())
}

let proxy = reqwest::Proxy::all("socks5://192.168.1.1:9000")?;
browse_with_proxy("https://www.google.com/invalid", proxy).await.unwrap();
```

    <!DOCTYPE html>
    <html lang=en>
      <meta charset=utf-8>
      <meta name=viewport content="initial-scale=1, minimum-scale=1, width=device-width">
      <title>Error 404 (Not Found)!!1</title>
      <style>
        *{margin:0;padding:0}html,code{font:15px/22px arial,sans-serif}html{background:#fff;color:#222;padding:15px}body{margin:7% auto 0;max-width:390px;min-height:180px;padding:30px 0 15px}* > body{background:url(//www.google.com/images/errors/robot.png) 100% 5px no-repeat;padding-right:205px}p{margin:11px 0 22px;overflow:hidden}ins{color:#777;text-decoration:none}a img{border:0}@media screen and (max-width:772px){body{background:none;margin-top:0;max-width:none;padding-right:0}}#logo{background:url(//www.google.com/images/branding/googlelogo/1x/googlelogo_color_150x54dp.png) no-repeat;margin-left:-5px}@media only screen and (min-resolution:192dpi){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat 0% 0%/100% 100%;-moz-border-image:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) 0}}@media only screen and (-webkit-min-device-pixel-ratio:2){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat;-webkit-background-size:100% 100%}}#logo{display:inline-block;height:54px;width:150px}
      </style>
      <a href=//www.google.com/><span id=logo aria-label=Google></span></a>
      <p><b>404.</b> <ins>That’s an error.</ins>
      <p>The requested URL <code>/invalid</code> was not found on this server.  <ins>That’s all we know.</ins>
    


#### 1.1.4 Building a Browser Struct

To encapsulate the techniques discussed into a cohesive tool, we can construct a `Browser` struct in Rust. This struct can encapsulate the configuration of cookies, user agents, and proxies, providing a modular and reusable solution for web browsing. The following is a simplified example, and in practice, additional error handling and feature customization would be necessary:

```rust
use reqwest;

struct Browser {
    client: reqwest::Client,
}

impl Browser {
    fn new() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
            .build()?;
        
        Ok(Browser { client })
    }

    async fn browse(&self, url: &str) -> Result<(), reqwest::Error> {
        let response = self.client.get(url).send().await?;
        println!("{}", response.text().await?);
        Ok(())
    }
}


fn main() {
    let browser = Browser::new().unwrap();
    browser.browse("http://www.google.com/invalid").await.unwrap();
}
```

In this example, the Browser struct is initialized with default configurations, and the browse method is used to make requests. This encapsulation facilitates the creation of a flexible and extensible browsing tool.

```sh
+-------------------------+
|    Browser Struct       |
|  Modular Web Browsing   |
+-------------------------+
            |
            V
+----------------------+
|  Initialize Browser  |
|  with Default Config |
+----------------------+
            |
            V
+--------------------------+
| Reqwest Client Config    |
|   - Cookies Enabled      |
|   - User-Agent Set       |
+--------------------------+
            |
            V
+--------------------------+
|   Browser Struct         |
|    (With Configured      |
|      Reqwest Client)     |
+--------------------------+
            |
            V
+--------------------------+
|  Browse Method           |
|  Make Request and Print  |
|             Response     |
+--------------------------+
            |
            V
+--------------------------+
|     Main Program         |
|  Create Browser Instance |
|  and Perform Web Browsing|
+--------------------------+
```


```Rust
use reqwest;

struct Browser {
    client: reqwest::Client,
}

impl Browser {
    fn new() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
            .build()?;
        
        Ok(Browser { client })
    }

    async fn browse(&self, url: &str) -> Result<(), reqwest::Error> {
        let response = self.client.get(url).send().await?;
        println!("{}", response.text().await?);
        Ok(())
    }
}

let browser = Browser::new().unwrap();
browser.browse("http://www.google.com/invalid").await.unwrap();
```

    <!DOCTYPE html>
    <html lang=en>
      <meta charset=utf-8>
      <meta name=viewport content="initial-scale=1, minimum-scale=1, width=device-width">
      <title>Error 404 (Not Found)!!1</title>
      <style>
        *{margin:0;padding:0}html,code{font:15px/22px arial,sans-serif}html{background:#fff;color:#222;padding:15px}body{margin:7% auto 0;max-width:390px;min-height:180px;padding:30px 0 15px}* > body{background:url(//www.google.com/images/errors/robot.png) 100% 5px no-repeat;padding-right:205px}p{margin:11px 0 22px;overflow:hidden}ins{color:#777;text-decoration:none}a img{border:0}@media screen and (max-width:772px){body{background:none;margin-top:0;max-width:none;padding-right:0}}#logo{background:url(//www.google.com/images/branding/googlelogo/1x/googlelogo_color_150x54dp.png) no-repeat;margin-left:-5px}@media only screen and (min-resolution:192dpi){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat 0% 0%/100% 100%;-moz-border-image:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) 0}}@media only screen and (-webkit-min-device-pixel-ratio:2){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat;-webkit-background-size:100% 100%}}#logo{display:inline-block;height:54px;width:150px}
      </style>
      <a href=//www.google.com/><span id=logo aria-label=Google></span></a>
      <p><b>404.</b> <ins>That’s an error.</ins>
      <p>The requested URL <code>/invalid</code> was not found on this server.  <ins>That’s all we know.</ins>
    


## 2. Social Engineering Automation

In the world of cybersecurity, social engineering plays a crucial role in orchestrating cyber attacks. Moving beyond conventional browsing, the automation of social engineering attacks with Rust becomes a strategic manner, harnessing the language's capabilities to manipulate user behavior effectively. This section not only explores the theoretical foundations but also delves into practical applications by demonstrating how Rust can serve as a crucial tool for social engineering in specific contexts, such as interacting with DuckDuckGo and Twitter.

Before launching any social-engineering attack, obtaining comprehensive information about the target is crucial. Rust's versatility extends beyond conventional web interactions, allowing for seamless communication with external services. In particular, Rust's capabilities facilitate interacting with the DuckDuckGo API, presenting a robust avenue for information gathering. This section of exploration dives into Rust's approach to querying DuckDuckGo, illustrating how the language can be employed for collecting relevant data and gaining valuable insights. By understanding and harnessing Rust's features for social engineering automation, individuals and organizations can enhance their cybersecurity practices and fortify defenses against evolving cyber threats.

### 2.1 DuckDuckGo API Interaction in Rust

Rust's `reqwest` library seamlessly integrates with DuckDuckGo's API, offering a Rustic interface to interact with the search giant's wealth of information. The following example showcases a basic Rust script that queries DuckDuckGo for search results:

```rust
use reqwest;

async fn duckduckgo_search(query: &str) -> Result<(), reqwest::Error> {
    let url = format!("https://api.duckduckgo.com/?q={}&format=json", query);

    let body = reqwest::get(&url).await?.text().await?;
    println!("{}", body);

    Ok(())
}

fn main() {
    duckduckgo_search("Rust programming language").await.unwrap();
}
```

This script queries DuckDuckGo for search results related to the Rust programming language.


```Rust
use reqwest;

async fn duckduckgo_search(query: &str) -> Result<(), reqwest::Error> {
    let url = format!("https://api.duckduckgo.com/?q={}&format=json", query);

    let body = reqwest::get(&url).await?.text().await?;
    println!("{}", body);

    Ok(())
}

duckduckgo_search("Rust programming language").await.unwrap();
```

    {"Abstract":"Rust is a multi-paradigm, general-purpose programming language that emphasizes performance, type safety, and concurrency. It enforces memory safety, meaning that all references point to valid memory, without requiring the use of automated memory management techniques such as garbage collection. To simultaneously enforce memory safety and prevent data races, its \"borrow checker\" tracks the object lifetime of all references in a program during compilation. Rust was influenced by ideas from functional programming, including immutability, higher-order functions, and algebraic data types. It is popular for systems programming. Software developer Graydon Hoare created Rust as a personal project while working at Mozilla Research in 2006. Mozilla officially sponsored the project in 2009. In the years following the first stable release in May 2015, Rust was adopted by companies including Amazon, Discord, Dropbox, Google, Meta, and Microsoft.","AbstractSource":"Wikipedia","AbstractText":"Rust is a multi-paradigm, general-purpose programming language that emphasizes performance, type safety, and concurrency. It enforces memory safety, meaning that all references point to valid memory, without requiring the use of automated memory management techniques such as garbage collection. To simultaneously enforce memory safety and prevent data races, its \"borrow checker\" tracks the object lifetime of all references in a program during compilation. Rust was influenced by ideas from functional programming, including immutability, higher-order functions, and algebraic data types. It is popular for systems programming. Software developer Graydon Hoare created Rust as a personal project while working at Mozilla Research in 2006. Mozilla officially sponsored the project in 2009. In the years following the first stable release in May 2015, Rust was adopted by companies including Amazon, Discord, Dropbox, Google, Meta, and Microsoft.","AbstractURL":"https://en.wikipedia.org/wiki/Rust_(programming_language)","Answer":"","AnswerType":"","Definition":"","DefinitionSource":"","DefinitionURL":"","Entity":"programming language","Heading":"Rust (programming language)","Image":"/i/832f249b.png","ImageHeight":200,"ImageIsLogo":1,"ImageWidth":200,"Infobox":{"content":[{"data_type":"string","label":"Designed by","value":"Graydon Hoare","wiki_order":0},{"data_type":"string","label":"Developer","value":"Rust Foundation","wiki_order":1},{"data_type":"string","label":"First appeared","value":"May 15, 2015","wiki_order":2},{"data_type":"string","label":"Implementation language","value":"Rust","wiki_order":3},{"data_type":"string","label":"Platform","value":"Cross-platform","wiki_order":4},{"data_type":"string","label":"OS","value":"Cross-platform","wiki_order":5},{"data_type":"string","label":"License","value":"MIT and Apache 2.0","wiki_order":6},{"data_type":"string","label":"Filename extensions","value":"rs.rlib","wiki_order":7},{"data_type":"github_profile","label":"GitHub profile","value":"rust-lang","wiki_order":"101"},{"data_type":"twitter_profile","label":"Twitter profile","value":"rustlang","wiki_order":"102"},{"data_type":"youtube_channel","label":"Youtube channel","value":"UCaYhcUwRBNscFNUKTjgPFiA","wiki_order":"105"},{"data_type":"instance","label":"Instance of","value":{"entity-type":"item","id":"Q28922885","numeric-id":28922885},"wiki_order":"207"},{"data_type":"instance_2","label":"Instance of","value":{"entity-type":"item","id":"Q3839507","numeric-id":3839507},"wiki_order":"207"},{"data_type":"instance_3","label":"Instance of","value":{"entity-type":"item","id":"Q12772052","numeric-id":12772052},"wiki_order":"207"},{"data_type":"instance_4","label":"Instance of","value":{"entity-type":"item","id":"Q21562092","numeric-id":21562092},"wiki_order":"207"},{"data_type":"instance_5","label":"Instance of","value":{"entity-type":"item","id":"Q4117397","numeric-id":4117397},"wiki_order":"207"},{"data_type":"instance_6","label":"Instance of","value":{"entity-type":"item","id":"Q506883","numeric-id":506883},"wiki_order":"207"},{"data_type":"instance_7","label":"Instance of","value":{"entity-type":"item","id":"Q651794","numeric-id":651794},"wiki_order":"207"},{"data_type":"instance_8","label":"Instance of","value":{"entity-type":"item","id":"Q9143","numeric-id":9143},"wiki_order":"207"},{"data_type":"wd_description","label":"Wikidata description","value":"memory-safe programming language without garbage collection","wiki_order":"210"},{"data_type":"wikidata_id","label":"Wikidata id","value":"Q575650","wiki_order":"211"}],"meta":[{"data_type":"string","label":"article_title","value":"Rust (programming language)"},{"data_type":"string","label":"template_name","value":"infobox programming language"},{"data_type":"string","label":"caption","value":"The official Rust logo"}]},"OfficialDomain":"rust-lang.org","OfficialWebsite":"https://foundation.rust-lang.org","Redirect":"","RelatedTopics":[{"FirstURL":"https://duckduckgo.com/c/Rust_(programming_language)","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/Rust_(programming_language)\">Rust (programming language) Category</a>","Text":"Rust (programming language) Category"},{"FirstURL":"https://duckduckgo.com/History_of_programming_languages","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/History_of_programming_languages\">History of programming languages</a> - The history of programming languages spans from documentation of early mechanical computers to modern tools for software development. Early programming languages were highly specialized, relying on mathematical notation and similarly obscure syntax.","Text":"History of programming languages - The history of programming languages spans from documentation of early mechanical computers to modern tools for software development. Early programming languages were highly specialized, relying on mathematical notation and similarly obscure syntax."},{"FirstURL":"https://duckduckgo.com/c/Pattern_matching_programming_languages","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/Pattern_matching_programming_languages\">Pattern matching programming languages</a>","Text":"Pattern matching programming languages"},{"FirstURL":"https://duckduckgo.com/c/Multi-paradigm_programming_languages","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/Multi-paradigm_programming_languages\">Multi-paradigm programming languages</a>","Text":"Multi-paradigm programming languages"},{"FirstURL":"https://duckduckgo.com/c/Statically_typed_programming_languages","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/Statically_typed_programming_languages\">Statically typed programming languages</a>","Text":"Statically typed programming languages"},{"FirstURL":"https://duckduckgo.com/c/Systems_programming_languages","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/Systems_programming_languages\">Systems programming languages</a>","Text":"Systems programming languages"},{"FirstURL":"https://duckduckgo.com/c/Concurrent_programming_languages","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/Concurrent_programming_languages\">Concurrent programming languages</a>","Text":"Concurrent programming languages"},{"FirstURL":"https://duckduckgo.com/c/High-level_programming_languages","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/High-level_programming_languages\">High-level programming languages</a>","Text":"High-level programming languages"},{"FirstURL":"https://duckduckgo.com/c/Mozilla","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/Mozilla\">Mozilla</a>","Text":"Mozilla"},{"FirstURL":"https://duckduckgo.com/c/Free_software_projects","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/Free_software_projects\">Free software projects</a>","Text":"Free software projects"},{"FirstURL":"https://duckduckgo.com/c/Functional_languages","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/Functional_languages\">Functional languages</a>","Text":"Functional languages"},{"FirstURL":"https://duckduckgo.com/c/Procedural_programming_languages","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/Procedural_programming_languages\">Procedural programming languages</a>","Text":"Procedural programming languages"},{"FirstURL":"https://duckduckgo.com/c/Free_compilers_and_interpreters","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/Free_compilers_and_interpreters\">Free compilers and interpreters</a>","Text":"Free compilers and interpreters"},{"FirstURL":"https://duckduckgo.com/c/Software_using_the_Apache_license","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/Software_using_the_Apache_license\">Software using the Apache license</a>","Text":"Software using the Apache license"},{"FirstURL":"https://duckduckgo.com/c/Software_using_the_MIT_license","Icon":{"Height":"","URL":"","Width":""},"Result":"<a href=\"https://duckduckgo.com/c/Software_using_the_MIT_license\">Software using the MIT license</a>","Text":"Software using the MIT license"}],"Results":[{"FirstURL":"https://foundation.rust-lang.org","Icon":{"Height":16,"URL":"/i/foundation.rust-lang.org.ico","Width":16},"Result":"<a href=\"https://foundation.rust-lang.org\"><b>Official site</b></a><a href=\"https://foundation.rust-lang.org\"></a>","Text":"Official site"}],"Type":"A","meta":{"attribution":null,"blockgroup":null,"created_date":null,"description":"Wikipedia","designer":null,"dev_date":null,"dev_milestone":"live","developer":[{"name":"DDG Team","type":"ddg","url":"http://www.duckduckhack.com"}],"example_query":"nikola tesla","id":"wikipedia_fathead","is_stackexchange":null,"js_callback_name":"wikipedia","live_date":null,"maintainer":{"github":"duckduckgo"},"name":"Wikipedia","perl_module":"DDG::Fathead::Wikipedia","producer":null,"production_state":"online","repo":"fathead","signal_from":"wikipedia_fathead","src_domain":"en.wikipedia.org","src_id":1,"src_name":"Wikipedia","src_options":{"directory":"","is_fanon":0,"is_mediawiki":1,"is_wikipedia":1,"language":"en","min_abstract_length":"20","skip_abstract":0,"skip_abstract_paren":0,"skip_end":"0","skip_icon":0,"skip_image_name":0,"skip_qr":"","source_skip":"","src_info":""},"src_url":null,"status":"live","tab":"About","topic":["productivity"],"unsafe":0}}


#### 2.1.1 Parsing DuckDuckGo Search Results

Interacting with the DuckDuckGo API is just the beginning; the real power lies in parsing and extracting meaningful information from the search results. Rust's capabilities in pattern matching and data manipulation become evident in the following example, where we parse and print the titles and URLs of search results:

```rust
use reqwest;
use serde_json::Value;

async fn parse_duckduckgo_results(query: &str) -> Result<(), reqwest::Error> {
    let url = format!("https://api.duckduckgo.com/?q={}&format=json", query);

    let body = reqwest::get(&url).await?.text().await?;
    let json: Value = serde_json::from_str(&body).unwrap();

    if let Some(results) = json["RelatedTopics"].as_array() {
        for result in results {
            if let Some(text) = result["Text"].as_str() {
                println!("Result: {}", text);
                println!("---");
            }
        }
    }

    Ok(())
}

fn main() {
    parse_duckduckgo_results("Rust programming language").await.unwrap();
}
```

In this example, the script queries DuckDuckGo parses the JSON response, and prints the titles and URLs of the search results. The serde_json crate facilitates JSON parsing in Rust.


```Rust
:dep serde_json = { version="1.0.108" }
```


```Rust
use reqwest;
use serde_json::Value;

async fn parse_duckduckgo_results(query: &str) -> Result<(), reqwest::Error> {
    let url = format!("https://api.duckduckgo.com/?q={}&format=json", query);

    let body = reqwest::get(&url).await?.text().await?;
    let json: Value = serde_json::from_str(&body).unwrap();

    if let Some(results) = json["RelatedTopics"].as_array() {
        for result in results {
            if let Some(text) = result["Text"].as_str() {
                println!("Result: {}", text);
                println!("---");
            }
        }
    }

    Ok(())
}

parse_duckduckgo_results("Rust programming language").await.unwrap();
```

    Result: Rust (programming language) Category
    ---
    Result: History of programming languages - The history of programming languages spans from documentation of early mechanical computers to modern tools for software development. Early programming languages were highly specialized, relying on mathematical notation and similarly obscure syntax.
    ---
    Result: Pattern matching programming languages
    ---
    Result: Multi-paradigm programming languages
    ---
    Result: Statically typed programming languages
    ---
    Result: Systems programming languages
    ---
    Result: Concurrent programming languages
    ---
    Result: High-level programming languages
    ---
    Result: Mozilla
    ---
    Result: Free software projects
    ---
    Result: Functional languages
    ---
    Result: Procedural programming languages
    ---
    Result: Free compilers and interpreters
    ---
    Result: Software using the Apache license
    ---
    Result: Software using the MIT license
    ---


### 2.2 Advanced DuckDuckGo Interactions
    
Beyond basic search queries, Rust empowers us to undertake more advanced interactions with the DuckDuckGo API. For instance, we can explore features like image search, news search, or even querying specific websites for information. Rust's flexibility allows for the expansion of capabilities based on the requirements of the reconnaissance.

#### 2.2.1 DuckDuckGo Image Search

Expanding our Rust script to include image search functionality involves modifying the DuckDuckGo API endpoint and adapting the parsing logic. The following example demonstrates a basic Rust script for querying DuckDuckGo for image search results:

```rust
use reqwest;
use serde_json::Value;

async fn duckduckgo_image_search(query: &str) -> Result<(), reqwest::Error> {
    let url = format!("https://api.duckduckgo.com/?q={}&format=json&iax=images&ia=images", query);

    let body = reqwest::get(&url).await?.text().await?;
    let json: Value = serde_json::from_str(&body).unwrap();

    if let Some(related_topics) = json["RelatedTopics"].as_array() {
        for topic in related_topics {
            if let Some(icon) = topic["Icon"].as_object() {
                if let Some(icon_url) = icon["URL"].as_str() {
                    if !icon_url.is_empty() {
                        let full_url = format!("https://duckduckgo.com{}", icon_url);
                        println!("Image URL: {}", full_url);
                        println!("---");
                    }
                }
            }
        }
    }

    Ok(())
}

fn main() {
    duckduckgo_image_search("Rust").await.unwrap();
}
```

In this example, the script queries DuckDuckGo for image search results related to the Rust programming language and prints the image URLs.


```Rust
use reqwest;
use serde_json::Value;

async fn duckduckgo_image_search(query: &str) -> Result<(), reqwest::Error> {
    let url = format!("https://api.duckduckgo.com/?q={}&format=json&iax=images&ia=images", query);

    let body = reqwest::get(&url).await?.text().await?;
    let json: Value = serde_json::from_str(&body).unwrap();

    if let Some(related_topics) = json["RelatedTopics"].as_array() {
        for topic in related_topics {
            if let Some(icon) = topic["Icon"].as_object() {
                if let Some(icon_url) = icon["URL"].as_str() {
                    if !icon_url.is_empty() {
                        let full_url = format!("https://duckduckgo.com{}", icon_url);
                        println!("Image URL: {}", full_url);
                        println!("---");
                    }
                }
            }
        }
    }

    Ok(())
}

duckduckgo_image_search("Rust").await.unwrap();
```

    Image URL: https://duckduckgo.com/i/2f16ac81.jpg
    ---
    Image URL: https://duckduckgo.com/i/832f249b.png
    ---
    Image URL: https://duckduckgo.com/i/playrust.com.ico
    ---


#### 2.2.2 Customized DuckDuckGo Searches

Tailoring DuckDuckGo searches to specific websites or domains enhances the precision of information retrieval. Rust's expressive syntax facilitates the creation of scripts that target particular domains or types of content. The following example illustrates a Rust script that searches for Rust-related content specifically on Wikipedia:

```rust
use reqwest;
use serde_json::Value;

async fn duckduckgo_web_search(query: &str, site: &str) -> Result<(), reqwest::Error> {
    let url = format!("https://api.duckduckgo.com/?q={}&site:{}&format=json", query, site);

    let body = reqwest::get(&url).await?.text().await?;
    let json: Value = serde_json::from_str(&body).unwrap();

    if let Some(results) = json["RelatedTopics"].as_array() {
        for result in results {
            if let (Some(title), Some(url)) = (result["Text"].as_str(), result["FirstURL"].as_str()) {
                println!("Title: {}", title);
                println!("URL: {}", url);
                println!("---");
            }
        }
    }

    Ok(())
}

fn main() {
    duckduckgo_web_search("rust", "wikipedia.org").await.unwrap();
}
```

In this example, the script queries DuckDuckGo for results related to the Rust programming language but restricts the search to the Wikipedia domain. This showcases the adaptability of Rust in tailoring searches to specific contexts.



```Rust
use reqwest;
use serde_json::Value;

async fn duckduckgo_web_search(query: &str, site: &str) -> Result<(), reqwest::Error> {
    let url = format!("https://api.duckduckgo.com/?q={}&site:{}&format=json", query, site);

    let body = reqwest::get(&url).await?.text().await?;
    let json: Value = serde_json::from_str(&body).unwrap();

    if let Some(results) = json["RelatedTopics"].as_array() {
        for result in results {
            if let (Some(title), Some(url)) = (result["Text"].as_str(), result["FirstURL"].as_str()) {
                println!("Title: {}", title);
                println!("URL: {}", url);
                println!("---");
            }
        }
    }

    Ok(())
}

duckduckgo_web_search("rust", "wikipedia.org").await.unwrap();
```

    Title: Rust An iron oxide, a usually reddish-brown oxide formed by the reaction of iron and oxygen in the...
    URL: https://duckduckgo.com/Rust
    ---
    Title: Rust (programming language) A multi-paradigm, general-purpose programming language.
    URL: https://duckduckgo.com/Rust_(programming_language)
    ---
    Title: Rust (video game) A multiplayer-only survival video game developed by Facepunch Studios.
    URL: https://duckduckgo.com/Rust_(video_game)
    ---


### 2.3 X Interaction in Rust

Social media platforms are a treasure of information, and X, formerly known as Twitter, with its wealth of real-time data, becomes a prime target for social engineering reconnaissance. In this section, we explore Rust's capabilities in interacting with Twitter API, parsing tweets, and extracting valuable insights.

#### 2.3.1 Parsing Xeets In Rust

Rust's `reqwest` library seamlessly integrates with the X API, providing a gateway to the vast ocean of tweets. The following example demonstrates a Rust script that queries X for xeets containing a specific hashtag:

```rust
use reqwest;
use serde_json::Value;
use base64::{Engine as _, engine::{self, general_purpose}};

async fn twitter_search(hashtag: &str) -> Result<(), reqwest::Error> {
    let consumer_key = "YOUR_TWITTER_CONSUMER_KEY";
    let consumer_secret = "YOUR_TWITTER_CONSUMER_SECRET";
    let access_token = "YOUR_TWITTER_ACCESS_TOKEN";
    let access_token_secret = "YOUR_TWITTER_ACCESS_TOKEN_SECRET";

    let bearer_token = general_purpose::STANDARD.encode(&format!("{}:{}", consumer_key, consumer_secret));
    let auth_header = format!("Basic {}", bearer_token);

    let auth_response = reqwest::Client::new()
        .post("https://api.twitter.com/oauth2/token")
        .header("Authorization", auth_header)
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await?
        .text()
        .await?;

    let auth_body: Value = serde_json::from_str(&auth_response).unwrap();
    let token = auth_body["access_token"].as_str().ok_or("Twitter API Auth Failed!").unwrap();

    let url = format!("https://api.twitter.com/2/tweets/search/recent?query=%23{}&max_results=5", hashtag);
    let response = reqwest::Client::new()
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?
        .text()
        .await?;

    let json: Value = serde_json::from_str(&response).unwrap();

    if let Some(data) = json["data"].as_array() {
        for tweet in data {
            if let Some(text) = tweet["text"].as_str() {
                println!("Tweet: {}", text);
                println!("---");
            }
        }
    }

    Ok(())
}


fn main() {
twitter_search("rustlang").await.unwrap();
}
```

Replace the placeholder values in the script with your actual X API credentials. This script queries X for recent tweets containing the specified hashtag and prints the text of the xeets.


```Rust
:dep base64 = {version="0.21.5"}
```


```Rust
use reqwest;
use serde_json::Value;
use base64::{Engine as _, engine::{self, general_purpose}};

async fn twitter_search(hashtag: &str) -> Result<(), reqwest::Error> {
    let consumer_key = "YOUR_TWITTER_CONSUMER_KEY";
    let consumer_secret = "YOUR_TWITTER_CONSUMER_SECRET";
    let access_token = "YOUR_TWITTER_ACCESS_TOKEN";
    let access_token_secret = "YOUR_TWITTER_ACCESS_TOKEN_SECRET";

    let bearer_token = general_purpose::STANDARD.encode(&format!("{}:{}", consumer_key, consumer_secret));
    let auth_header = format!("Basic {}", bearer_token);

    let auth_response = reqwest::Client::new()
        .post("https://api.twitter.com/oauth2/token")
        .header("Authorization", auth_header)
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await?
        .text()
        .await?;

    let auth_body: Value = serde_json::from_str(&auth_response).unwrap();
    let token = auth_body["access_token"].as_str().ok_or("Twitter API Auth Failed!").unwrap();

    let url = format!("https://api.twitter.com/2/tweets/search/recent?query=%23{}&max_results=5", hashtag);
    let response = reqwest::Client::new()
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?
        .text()
        .await?;

    let json: Value = serde_json::from_str(&response).unwrap();
    println!("Tweet: {}", json);
    if let Some(data) = json["data"].as_array() {
        for tweet in data {
            if let Some(text) = tweet["text"].as_str() {
                println!("Tweet: {}", text);
                println!("---");
            }
        }
    }

    Ok(())
}

twitter_search("rustlang").await.unwrap();
```

    Tweet: {"client_id":"28218887","detail":"When authenticating requests to the Twitter API v2 endpoints, you must use keys and tokens from a Twitter developer App that is attached to a Project. You can create a project via the developer portal.","reason":"client-not-enrolled","registration_url":"https://developer.twitter.com/en/docs/projects/overview","required_enrollment":"Appropriate Level of API Access","title":"Client Forbidden","type":"https://api.twitter.com/2/problems/client-forbidden"}


As the output suggests, we are encountering Twitter API call failures with the error message "Client Forbidden" and we are prompted to upgrade from the free plan to the basic plan. [As of the recent announcement](https://twittercommunity.com/t/announcing-the-users-search-and-trends-lookup-endpoints-in-the-x-api-v2/210567), X API v2 introduces two new endpoints, Users Search and Trends lookup, available exclusively to developers with Pro access in the X API.

### 2.4 Advanced Social Engineering

Social engineering extends beyond web reconnaissance, encompassing email manipulation and mass social engineering. In this section, we explore advanced Rust scripts that interact with email services, send anonymous emails, and orchestrate mass social engineering attacks.

#### 2.4.1 Anonymous Email Communication

Maintaining anonymity extends beyond web browsing into email communication. Rust's capabilities enable us to interact with email services and send anonymous emails. The following example demonstrates a Rust script that sends an anonymous email using the Reqwest library:

```rust
use reqwest;
use serde_json::Value;

async fn send_anonymous_email(subject: &str, body: &str) -> Result<(), reqwest::Error> {
    let sender_email = "your_sender_email@example.com";
    let receiver_email = "recipient@example.com";
    let api_key = "YOUR_EMAIL_API_KEY";

    let url = format!("https://api.mailgun.net/v3/YOUR_DOMAIN_NAME/messages");
    let client = reqwest::Client::new();

    let response = client.post(&url)
        .basic_auth("api", Some(api_key))
        .form(&[
            ("from", format!("Anonymous <{}>", sender_email)),
            ("to", receiver_email.to_string()),
            ("subject", subject.to_string()),
            ("text", body.to_string()),
        ])
        .send()
        .await?
        .text()
        .await?;


    let json: Value = serde_json::from_str(&response).unwrap();
    
    if let Some(message) = json["message"].as_str() {
        println!("Email Sent: {}", message);
    }

    Ok(())
}

fn main() {
    send_anonymous_email("Hello World", "This is an anonymous email sent from Rust.").await.unwrap();
}
```

Replace the placeholder values in the script with your actual sender email, receiver email, domain name, and [**Mailgun API key**](https://app.mailgun.com/settings/api_security). This script sends an anonymous email using the Mailgun email service.


```Rust
use reqwest;
use serde_json::Value;

async fn send_anonymous_email(subject: &str, body: &str) -> Result<(), reqwest::Error> {
    let sender_email = "your_sender_email@example.com";
    let receiver_email = "recipient@example.com";
    let api_key = "YOUR_EMAIL_API_KEY";

    let url = format!("https://api.mailgun.net/v3/YOUR_DOMAIN_NAME/messages");
    let client = reqwest::Client::new();

    let response = client.post(&url)
        .basic_auth("api", Some(api_key))
        .form(&[
            ("from", format!("Anonymous <{}>", sender_email)),
            ("to", receiver_email.to_string()),
            ("subject", subject.to_string()),
            ("text", body.to_string()),
        ])
        .send()
        .await?
        .text()
        .await?;

    let json: Value = serde_json::from_str(&response).unwrap();
    
    if let Some(message) = json["message"].as_str() {
        println!("Email Sent: {}", message);
    }

    Ok(())
}

send_anonymous_email("Hello World", "This is an anonymous email sent from Rust.").await.unwrap();
```

    Email Sent: Queued. Thank you.


![Email](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/7xc4fkz7e1h4w5issfsu.png)

### 2.4.2 Mass Social Engineering

Mass social engineering requires automation, and Rust excels in providing the tools necessary for orchestrating large-scale attacks. The following example illustrates a Rust script that utilizes the `reqwest` library to send spear-phishing emails to multiple targets:

```rust
use reqwest;
use serde_json::Value;

async fn send_spear_phishing_email(subject: &str, body: &str, recipients: Vec<&str>) -> Result<(), reqwest::Error> {
    let sender_email = "your_sender_email@example.com";
    let api_key = "YOUR_EMAIL_API_KEY";

    let url = format!("https://api.mailgun.net/v3/YOUR_DOMAIN_NAME/messages");
    let client = reqwest::Client::new();

    let recipient_emails = recipients.join(",");
    
    let response = client.post(&url)
        .basic_auth("api", Some(api_key))
        .form(&[
            ("from", format!("Anonymous <{}>", sender_email)),
            ("to", recipient_emails),
            ("subject", subject.to_string()),
            ("text", body.to_string()),
        ])
        .send()
        .await?
        .text()
        .await?;

    let json: Value = serde_json::from_str(&response).unwrap();
    
    if let Some(message) = json["message"].as_str() {
        println!("Email Sent: {}", message);
    }

    Ok(())
}

fn main() {
    let target_emails = ["target1@example.com", "target2@example.com", "target3@example.com"];
    send_spear_phishing_email("Important Security Update", "Dear User, we require you to update your credentials immediately.", target_emails).await.unwrap();
}
```

Replace the placeholder values in the script with your actual [**Mailgun API key**](https://app.mailgun.com/settings/api_security). This script utilizes the `reqwest` library to send spear-phishing emails to multiple targets, demonstrating the scalability and automation capabilities of Rust in the world of social engineering.


```Rust
use reqwest;
use serde_json::Value;

async fn send_spear_phishing_email(subject: &str, body: &str, recipients: Vec<&str>) -> Result<(), reqwest::Error> {
    let sender_email = "your_sender_email@example.com";
    let api_key = "YOUR_EMAIL_API_KEY";

    let url = format!("https://api.mailgun.net/v3/YOUR_DOMAIN_NAME/messages");
    let client = reqwest::Client::new();

    let recipient_emails = recipients.join(",");
    
    let response = client.post(&url)
        .basic_auth("api", Some(api_key))
        .form(&[
            ("from", format!("Anonymous <{}>", sender_email)),
            ("to", recipient_emails),
            ("subject", subject.to_string()),
            ("text", body.to_string()),
        ])
        .send()
        .await?
        .text()
        .await?;

    let json: Value = serde_json::from_str(&response).unwrap();
    
    if let Some(message) = json["message"].as_str() {
        println!("Email Sent: {}", message);
    }

    Ok(())
}

let target_emails = ["target1@example.com", "target2@example.com", "target3@example.com"];
send_spear_phishing_email("Important Security Update", "Dear User, we require you to update your credentials immediately.", target_emails).await.unwrap();
```

    Email Sent: Queued. Thank you.


![Email](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/827m52maup7h6g1yxey1.png)

### 3. Conclusion

In this extensive exploration, we've witnessed the fusion of character and technology in the world of web reconnaissance using Rust. From anonymously browsing the Internet and interacting with DuckDuckGo and X to advanced social engineering techniques, Rust has proven to be a versatile and robust language for cybersecurity professionals. As we navigate the evolving landscape of cyber threats, Rust stands as a sweet companion, empowering us to safeguard digital landscapes with resilience.

---
---
