@load base/frameworks/notice

redef enum Notice::Type += {
    HighConnectionCount
};

const notice_threshold: count = 10;
const notice_time_window: interval = 1min;

const ip_connection_count: table[addr] of count = table();
const ip_last_seen: table[addr] of time = table();

event connection_established(c: connection) {
    local ip = c$id$resp_h;

    if (ip in ip_connection_count) {
        ip_connection_count[ip] += 1;
    } else {
        ip_connection_count[ip] = 1;
    }

    ip_last_seen[ip] = current_time();

    local recent_connections = 0;
    for (ip_conn in ip_connection_count) {
        recent_connections += ip_connection_count[ip_conn];
    }

    if (recent_connections >= notice_threshold) {
        local msg = fmt("High connection count detected for IP %s: %d connections in the last %s", ip, recent_connections, notice_time_window);
        NOTICE([$note=HighConnectionCount, $msg=msg]);
    }

    for (ip_conn in ip_connection_count) {
        if (current_time() - ip_last_seen[ip_conn] > notice_time_window) {
            delete ip_connection_count[ip_conn];
            delete ip_last_seen[ip_conn];
        }
    }
}
