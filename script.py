import os
import uuid
import time
from datetime import datetime
import json
import sys
import requests
import re
import html
import urllib3
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
import tkinter as tk
from tkinter import simpledialog
import getpass

def gui_getpass(prompt="Введите пароль: "):
    pwd = simpledialog.askstring("Авторизация", prompt, show="*")
    return pwd
getpass.getpass = gui_getpass

from auth import auth

disable_warnings(InsecureRequestWarning)

def parse_config():
    with open(f"SIEM.json", "r", encoding="utf-8") as f:
        result = json.loads(f.read())
        return result

targets = parse_config()

uuid_val = sys.argv[1]
time_from = sys.argv[2]
time_to = sys.argv[3]

TimeFromUI = time_from
TimeToUI = time_to

date_format = "%d-%m-%Y %H:%M"
timeFrom = int(datetime.strptime(TimeFromUI, date_format).timestamp())
timeTo = int(datetime.strptime(TimeToUI, date_format).timestamp())

uuid = uuid_val

final_json_data = {
    "filter": f'filter(uuid = \"{uuid}\") | select(_checkpoint, _presentation, _whitelisting, action, agent_id, aggregation_name, alert.context, alert.ioc_description, alert.ioc_importance, alert.ioc_provider, alert.ioc_type, alert.ioc_value, alert.key, alert.regex_match, asset_ids, assigned_dst_host, assigned_dst_ip, assigned_dst_port, assigned_src_host, assigned_src_ip, assigned_src_port, bad.clustering.cluster_id, bad.clustering.cluster_size, bad.clustering.reduction_coef, bad.hack_tracker.is_hacker, bad.hack_tracker.root_process, bad.risk_score, bad.risk_score_raw, bad.triggered_models, bad.triggered_rule_score_raw, body, category.generic, category.high, category.low, chain_id, correlation_name, correlation_type, count, count.bytes, count.bytes_in, count.bytes_out, count.packets, count.packets_in, count.packets_out, count.subevents, datafield1, datafield10, datafield11, datafield12, datafield13, datafield14, datafield15, datafield16, datafield17, datafield18, datafield19, datafield2, datafield20, datafield3, datafield4, datafield5, datafield6, datafield7, datafield8, datafield9, detect, direction, dst.asset, dst.fqdn, dst.geo.asn, dst.geo.city, dst.geo.country, dst.geo.org, dst.host, dst.hostname, dst.ip, dst.mac, dst.mac.vendor, dst.port, duration, event_src.asset, event_src.category, event_src.description, event_src.fqdn, event_src.host, event_src.hostname, event_src.id, event_src.ip, event_src.mac, event_src.mac.vendor, event_src.provider, event_src.rule, event_src.subsys, event_src.title, event_src.vendor, event_type, external_dst.fqdn, external_dst.geo.asn, external_dst.geo.city, external_dst.geo.country, external_dst.geo.org, external_dst.host, external_dst.hostname, external_dst.ip, external_dst.mac, external_dst.mac.vendor, external_link, external_src.fqdn, external_src.geo.asn, external_src.geo.city, external_src.geo.country, external_src.geo.org, external_src.host, external_src.hostname, external_src.ip, external_src.mac, external_src.mac.vendor, generator, generator.type, generator.version, historical, id, importance, incident.attacking_addresses, incident.attacking_assets, incident.compromised_assets, incident.related_addresses, incident.related_assets, incorrect_time, input_id, interface, job_id, labels, logon_auth_method, logon_service, logon_type, mime, msgid, nas_fqdn, nas_ip, normalized, numfield1, numfield2, numfield3, numfield4, numfield5, object, object.account.company, object.account.contact, object.account.department, object.account.dn, object.account.domain, object.account.fullname, object.account.group, object.account.id, object.account.name, object.account.privileges, object.account.provider, object.account.session_id, object.account.title, object.application.account.domain, object.application.account.id, object.application.account.name, object.application.account.privileges, object.application.account.session_id, object.application.name, object.domain, object.fullpath, object.group, object.hash, object.hash.imphash, object.hash.md5, object.hash.sha1, object.hash.sha256, object.id, object.meta, object.name, object.new_value, object.num_value, object.original_name, object.path, object.process.chain, object.process.chain_info, object.process.cmdline, object.process.cwd, object.process.decoded_data, object.process.fullpath, object.process.guid, object.process.hash, object.process.hash.imphash, object.process.hash.md5, object.process.hash.sha1, object.process.hash.sha256, object.process.id, object.process.meta, object.process.name, object.process.original_name, object.process.parent.cmdline, object.process.parent.decoded_data, object.process.parent.fullpath, object.process.parent.guid, object.process.parent.hash, object.process.parent.hash.imphash, object.process.parent.hash.md5, object.process.parent.hash.sha1, object.process.parent.hash.sha256, object.process.parent.id, object.process.parent.name, object.process.parent.path, object.process.path, object.process.version, object.property, object.query, object.state, object.storage.fullpath, object.storage.id, object.storage.name, object.storage.path, object.type, object.value, object.vendor, object.version, origin_app_alias, origin_app_id, origin_app_name, original_time, primary_siem_app_alias, primary_siem_app_id, primary_siem_app_name, protocol, protocol.layer7, reason, recv_asset, recv_host, recv_ipv4, recv_ipv6, recv_time, related_events, related_events.time, remote, scope_id, siem_alias, siem_id, site_address, site_alias, site_id, site_name, src.asset, src.fqdn, src.geo.asn, src.geo.city, src.geo.country, src.geo.org, src.host, src.hostname, src.ip, src.mac, src.mac.vendor, src.port, start_time, status, storage_app_alias, storage_app_id, storage_app_name, subevents, subevents.missed, subject, subject.account.company, subject.account.contact, subject.account.department, subject.account.dn, subject.account.domain, subject.account.fullname, subject.account.group, subject.account.id, subject.account.name, subject.account.privileges, subject.account.provider, subject.account.session_id, subject.account.title, subject.application.account.domain, subject.application.account.id, subject.application.account.name, subject.application.account.privileges, subject.application.account.session_id, subject.application.name, subject.domain, subject.group, subject.id, subject.name, subject.privileges, subject.process.chain, subject.process.chain_info, subject.process.cmdline, subject.process.cwd, subject.process.decoded_data, subject.process.fullpath, subject.process.guid, subject.process.hash, subject.process.hash.imphash, subject.process.hash.md5, subject.process.hash.sha1, subject.process.hash.sha256, subject.process.id, subject.process.meta, subject.process.name, subject.process.original_name, subject.process.parent.cmdline, subject.process.parent.decoded_data, subject.process.parent.fullpath, subject.process.parent.guid, subject.process.parent.hash, subject.process.parent.hash.imphash, subject.process.parent.hash.md5, subject.process.parent.hash.sha1, subject.process.parent.hash.sha256, subject.process.parent.id, subject.process.parent.name, subject.process.parent.path, subject.process.path, subject.process.version, subject.state, subject.type, subject.version, tag, task_id, taxonomy_version, tcp_flag, tenant_id, text, time, type, uuid) | sort(time desc)',
    "groupValues": [],
    "timeFrom": timeFrom,
    "timeTo": timeTo
}

for target in targets:
    session = auth(target, timeout=300)
    session.verify = False

    # Изначальное событие
    daughter_post = session.post(
        "" + target["url"] + "/api/events/v3/events",
        json = final_json_data,
        verify=False
    )

    daughter_json = json.loads(daughter_post.text)
    all_parents_data = []
    filters_stack = []
    required_fields = ["time", "event_src.host", "action", "status", "text", "subject.account.name", "object.process.fullpath", "uuid"]

    daughter_events = daughter_json.get('events', [])

    for item in daughter_events:
        extracted_data = {f: item.get(f) for f in required_fields if f in item}
        curr_uuid = item.get("uuid")
        
        extracted_data["uuid"] = curr_uuid
        extracted_data["child_uuid"] = None
        all_parents_data.append(extracted_data)
        
        host_value = extracted_data.get("event_src.host")
        parent_conditions = [
            f'({k.replace(".parent", "")} = "{str(v).replace("\\", "\\\\")}")'
            for k, v in item.items()
            if ".parent." in k and v is not None
        ]
        
        if parent_conditions:
            parent_conditions.append(f'(event_src.host = "{host_value}")')
            filter_query = " AND ".join(parent_conditions)
            filters_stack.append((filter_query, curr_uuid))

    while filters_stack:
        current_filter, child_uuid = filters_stack.pop()
        
        parent_json_data = {
            "filter": f'filter({current_filter}) | select(_checkpoint, _presentation, _whitelisting, action, agent_id, aggregation_name, alert.context, alert.ioc_description, alert.ioc_importance, alert.ioc_provider, alert.ioc_type, alert.ioc_value, alert.key, alert.regex_match, asset_ids, assigned_dst_host, assigned_dst_ip, assigned_dst_port, assigned_src_host, assigned_src_ip, assigned_src_port, bad.clustering.cluster_id, bad.clustering.cluster_size, bad.clustering.reduction_coef, bad.hack_tracker.is_hacker, bad.hack_tracker.root_process, bad.risk_score, bad.risk_score_raw, bad.triggered_models, bad.triggered_rule_score_raw, body, category.generic, category.high, category.low, chain_id, correlation_name, correlation_type, count, count.bytes, count.bytes_in, count.bytes_out, count.packets, count.packets_in, count.packets_out, count.subevents, datafield1, datafield10, datafield11, datafield12, datafield13, datafield14, datafield15, datafield16, datafield17, datafield18, datafield19, datafield2, datafield20, datafield3, datafield4, datafield5, datafield6, datafield7, datafield8, datafield9, detect, direction, dst.asset, dst.fqdn, dst.geo.asn, dst.geo.city, dst.geo.country, dst.geo.org, dst.host, dst.hostname, dst.ip, dst.mac, dst.mac.vendor, dst.port, duration, event_src.asset, event_src.category, event_src.description, event_src.fqdn, event_src.host, event_src.hostname, event_src.id, event_src.ip, event_src.mac, event_src.mac.vendor, event_src.provider, event_src.rule, event_src.subsys, event_src.title, event_src.vendor, event_type, external_dst.fqdn, external_dst.geo.asn, external_dst.geo.city, external_dst.geo.country, external_dst.geo.org, external_dst.host, external_dst.hostname, external_dst.ip, external_dst.mac, external_dst.mac.vendor, external_link, external_src.fqdn, external_src.geo.asn, external_src.geo.city, external_src.geo.country, external_src.geo.org, external_src.host, external_src.hostname, external_src.ip, external_src.mac, external_src.mac.vendor, generator, generator.type, generator.version, historical, id, importance, incident.attacking_addresses, incident.attacking_assets, incident.compromised_assets, incident.related_addresses, incident.related_assets, incorrect_time, input_id, interface, job_id, labels, logon_auth_method, logon_service, logon_type, mime, msgid, nas_fqdn, nas_ip, normalized, numfield1, numfield2, numfield3, numfield4, numfield5, object, object.account.company, object.account.contact, object.account.department, object.account.dn, object.account.domain, object.account.fullname, object.account.group, object.account.id, object.account.name, object.account.privileges, object.account.provider, object.account.session_id, object.account.title, object.application.account.domain, object.application.account.id, object.application.account.name, object.application.account.privileges, object.application.account.session_id, object.application.name, object.domain, object.fullpath, object.group, object.hash, object.hash.imphash, object.hash.md5, object.hash.sha1, object.hash.sha256, object.id, object.meta, object.name, object.new_value, object.num_value, object.original_name, object.path, object.process.chain, object.process.chain_info, object.process.cmdline, object.process.cwd, object.process.decoded_data, object.process.fullpath, object.process.guid, object.process.hash, object.process.hash.imphash, object.process.hash.md5, object.process.hash.sha1, object.process.hash.sha256, object.process.id, object.process.meta, object.process.name, object.process.original_name, object.process.parent.cmdline, object.process.parent.decoded_data, object.process.parent.fullpath, object.process.parent.guid, object.process.parent.hash, object.process.parent.hash.imphash, object.process.parent.hash.md5, object.process.parent.hash.sha1, object.process.parent.hash.sha256, object.process.parent.id, object.process.parent.name, object.process.parent.path, object.process.path, object.process.version, object.property, object.query, object.state, object.storage.fullpath, object.storage.id, object.storage.name, object.storage.path, object.type, object.value, object.vendor, object.version, origin_app_alias, origin_app_id, origin_app_name, original_time, primary_siem_app_alias, primary_siem_app_id, primary_siem_app_name, protocol, protocol.layer7, reason, recv_asset, recv_host, recv_ipv4, recv_ipv6, recv_time, related_events, related_events.time, remote, scope_id, siem_alias, siem_id, site_address, site_alias, site_id, site_name, src.asset, src.fqdn, src.geo.asn, src.geo.city, src.geo.country, src.geo.org, src.host, src.hostname, src.ip, src.mac, src.mac.vendor, src.port, start_time, status, storage_app_alias, storage_app_id, storage_app_name, subevents, subevents.missed, subject, subject.account.company, subject.account.contact, subject.account.department, subject.account.dn, subject.account.domain, subject.account.fullname, subject.account.group, subject.account.id, subject.account.name, subject.account.privileges, subject.account.provider, subject.account.session_id, subject.account.title, subject.application.account.domain, subject.application.account.id, subject.application.account.name, subject.application.account.privileges, subject.application.account.session_id, subject.application.name, subject.domain, subject.group, subject.id, subject.name, subject.privileges, subject.process.chain, subject.process.chain_info, subject.process.cmdline, subject.process.cwd, subject.process.decoded_data, subject.process.fullpath, subject.process.guid, subject.process.hash, subject.process.hash.imphash, subject.process.hash.md5, subject.process.hash.sha1, subject.process.hash.sha256, subject.process.id, subject.process.meta, subject.process.name, subject.process.original_name, subject.process.parent.cmdline, subject.process.parent.decoded_data, subject.process.parent.fullpath, subject.process.parent.guid, subject.process.parent.hash, subject.process.parent.hash.imphash, subject.process.parent.hash.md5, subject.process.parent.hash.sha1, subject.process.parent.hash.sha256, subject.process.parent.id, subject.process.parent.name, subject.process.parent.path, subject.process.path, subject.process.version, subject.state, subject.type, subject.version, tag, task_id, taxonomy_version, tcp_flag, tenant_id, text, time, type, uuid) | sort(time desc)',
            "groupValues": [],
            "timeFrom": timeFrom,
            "timeTo": timeTo
        }
        
        try:
            parent_post = session.post(
                "" + target["url"] + "/api/events/v3/events",
                json = parent_json_data,
                verify=False
            )
            found_events = parent_post.json().get('events', [])
        except Exception:
            continue

        for item in found_events:
            curr_uuid = item.get("uuid")
            
            node_data = {f: item.get(f) for f in required_fields if f in item}
            node_data["uuid"] = curr_uuid
            node_data["child_uuid"] = child_uuid
            all_parents_data.append(node_data)

            host_val = item.get("event_src.host")
            conditions = [
                f'({k.replace(".parent", "")} = "{str(v).replace("\\", "\\\\")}")'
                for k, v in item.items()
                if ".parent." in k and v is not None
            ]

            if conditions:
                conditions.append(f'(event_src.host = "{host_val}")')
                next_filter = " AND ".join(conditions)
                filters_stack.append((next_filter, curr_uuid))

def build_html_tree(nodes, current_child_uuid=None):
    level_nodes = [n for n in nodes if n.get('child_uuid') == current_child_uuid]
    if not level_nodes:
        return ""

    html = "<div class='branch'>"
    for node in level_nodes:
        fields_html = f"<div class='node-uuid'>UUID: {node.get('uuid', 'N/A')}</div>"
        for field in required_fields:
            if field != 'uuid':
                fields_html += f"<div class='node-field'><b>{field}:</b> {node.get(field, '-')}</div>"

        parents_html = build_html_tree(nodes, node.get('uuid'))
        
        # Если есть родители, рисуем стрелку
        connector = "<div class='connector-wrapper'><div class='line'></div><div class='arrow'></div></div>" if parents_html else ""
        
        html += f"""
        <div class='node-container'>
            <div class='node-card'>{fields_html}</div>
            {connector}
            {parents_html}
        </div>
        """
    html += "</div>"
    return html

html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: 'Courier New', monospace; background: #fff; color: #000; padding: 50px; white-space: nowrap; }}
        .tree-wrapper {{ display: flex; align-items: flex-start; }}
        .branch {{ display: flex; flex-direction: column; justify-content: center; }}
        .node-container {{ display: flex; align-items: center; margin: 15px 0; }}
        
        /* Карточка */
        .node-card {{ 
            border: 2px solid #000; padding: 12px; background: #fff; 
            min-width: 320px; box-shadow: 6px 6px 0px #000; z-index: 5;
        }}
        .node-uuid {{ font-weight: bold; border-bottom: 2px solid #000; margin-bottom: 8px; padding-bottom: 4px; }}
        .node-field {{ font-size: 13px; margin: 3px 0; white-space: normal; }}
        
        /* Коннектор со стрелкой */
        .connector-wrapper {{ display: flex; align-items: center; flex-shrink: 0; }}
        .line {{ width: 30px; height: 2px; background: #000; }}
        .arrow {{ 
            width: 10px; height: 10px; background: #000; 
            clip-path: polygon(0% 0%, 100% 50%, 0% 100%); /* Треугольник */
            margin-left: -2px; 
        }}

        /* Выделение корня */
        .node-container:only-child > .node-card {{ border-width: 3px; }}
    </style>
</head>
<body>
    <h2>O2 DEMO (Daughter &rarr; Parents)</h2>
    <div class="tree-wrapper">
        {build_html_tree(all_parents_data, None)}
    </div>
</body>
</html>
"""

with open("process_tree.html", "w", encoding="utf-8") as f:
    f.write(html_template)
