###接口列表
1. getHostId : 获取主机的ID，如果当前不存在则为该主机新生成一个(h2c)<br>
    to {'mac':'','transIp':""}  <br>
    back : {'id':'','state':t/f}
    <br>
2. createContainer : 生成一个容器(c2h) <br>
    to : { ip : "", image : "",host:""} <br>
    back : {serialId : "", container : obj,netns : obj}
