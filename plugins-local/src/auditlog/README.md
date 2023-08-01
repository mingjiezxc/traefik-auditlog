# 根据 插件 组合 修改
https://github.com/traefik/plugin-rewritebody
https://github.com/23deg/jwt-middleware

# 作用
1. 检查 & 校验 jwt 是否 正确 与 有效
2. 将 请求 & 返回 写进数据库





# database 
   数据库使用经 postgrest 写入 

## postgresql.conf
postgresql.conf add shared_preload_libraries
```conf
shared_preload_libraries = 'timescaledb'
```


```sql
CREATE EXTENSION timescaledb;

CREATE TABLE audit_log (
    time        TIMESTAMPTZ       NOT NULL,
    account varchar(50) NULL,
    code  int NULL,
    host varchar(512) NULL,
    remote_addr varchar(512) NULL,
    x_forwarded_for varchar(512) NULL,
    request_uri text NOT NULL,
    request_method varchar(10) NOT NULL,
    request_body text NULL,
    response_body text NULL,
);

SELECT create_hypertable('audit_log', 'time');

SELECT set_chunk_time_interval('audit_log', INTERVAL '168 hours');
```