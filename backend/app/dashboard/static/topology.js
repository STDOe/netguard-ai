import {api, byId, click, el, option, pathId} from './common.js';

const styles = [
  {selector: 'node', style: {'shape': 'round-rectangle', 'width': 46, 'height': 35, 'background-color': '#8fb3ff', 'border-color': '#0d1522', 'border-width': 3,
    'label': 'data(label)', 'font-size': 11, 'color': '#e6edf5', 'text-wrap': 'wrap', 'text-max-width': 110, 'text-margin-y': 9, 'text-valign': 'bottom'}},
  {selector: '.core', style: {'shape': 'diamond', 'background-color': '#5ce0ed', 'width': 52, 'height': 44}},
  {selector: '.zone', style: {'shape': 'ellipse', 'background-color': '#88dfb8', 'width': 27, 'height': 27}},
  {selector: '.honeypot', style: {'shape': 'hexagon', 'background-color': '#eab86e'}},
  {selector: '.observed', style: {'border-color':'#f6cd83', 'border-width':4}},
  {selector: 'node:selected', style: {'border-color': '#fff', 'border-width': 4}},
  {selector: 'edge', style: {'width': 2, 'line-color': '#537391', 'curve-style': 'bezier'}},
  {selector: '.membership', style: {'width': 1, 'line-style': 'dashed', 'line-color': '#41636c'}}
];

export function mountGraph(container, elements, layout = 'breadthfirst', roots) {
  return window.cytoscape({container, elements, style: styles, minZoom: .3, maxZoom: 3,
    layout: {name: layout, directed: true, roots, padding: 27, animate: false}});
}

export function elementsFromNetwork(network) {
  const iface = new Map();
  const subnets = new Map(network.subnets.map(item => [item.id, item]));
  const vlans = new Map(network.vlans.map(item => [item.id, item]));
  const zones = new Map(network.zones.map(item => [item.id, item]));
  const elements = [];
  for (const device of network.devices) {
    const attached = new Set();
    for (const port of device.interfaces) {
      iface.set(port.id, device.id);
      const vlan = vlans.get(subnets.get(port.subnet_id)?.vlan_id);
      if (vlan) attached.add(vlan.zone_id);
    }
    const inHoneypot = [...attached].some(id => zones.get(id)?.name.toLowerCase().includes('honeypot'));
    elements.push({data: {id: device.id, label: device.name},
      classes: device.capabilities.zone_firewall ? 'core' : inHoneypot ? 'honeypot' : 'spoke'});
    for (const zone of attached) {
      elements.push({data: {id: `${device.id}-${zone}`, source: device.id, target: zone}, classes: 'membership'});
    }
  }
  for (const zone of network.zones) {
    elements.push({data: {id: zone.id, label: zone.name}, classes: zone.name.toLowerCase().includes('honeypot') ? 'zone honeypot' : 'zone'});
  }
  for (const link of network.links) {
    elements.push({data: {id: link.id, source: iface.get(link.endpoints[0]), target: iface.get(link.endpoints[1])}});
  }
  return elements;
}

export function mapPanel(reload) {
  const container = byId('network-map');
  const select = byId('device');
  let graph;
  let network;
  let key;
  let observed = new Set();
  function details() {
    const device = network.devices.find(item => item.id === select.value);
    if (!device) return;
    graph.nodes().unselect();
    graph.getElementById(device.id).select();
    const data = el('dl');
    const rows = [['Platform', `${device.platform} · ${device.version}`],
      ['Reachability', 'Unknown · mock'], ['Honeypot', observed.has(device.id) ? 'Sensor observation on this revision' : 'No matched event in recent feed'], ['Zone firewall', device.capabilities.zone_firewall ? 'Modeled' : 'Unavailable'],
      ['Routing protocols', device.routing_protocols.join(', ') || 'None'],
      ['Supported routing', device.capabilities.routing_protocols.join(', ') || 'None']];
    for (const [title, value] of rows) data.append(el('dt', title), el('dd', value));
    const ports = el('ul');
    for (const port of device.interfaces) {
      const subnet = network.subnets.find(item => item.id === port.subnet_id);
      const vlan = network.vlans.find(item => item.id === subnet?.vlan_id);
      ports.append(el('li', `${port.name} · ${port.address} · ${subnet?.prefix ?? 'unknown subnet'}${vlan ? ` · VLAN ${vlan.tag}` : ''}`));
    }
    const routes = el('ul');
    for (const route of device.routes) routes.append(el('li', `${route.destination} via ${route.next_hop}`));
    if (!routes.children.length) routes.append(el('li', 'No static routes.', 'muted'));
    byId('device-detail').replaceChildren(data, el('h3', 'Interfaces'), ports, el('h3', 'Routes'), routes);
  }
  select.addEventListener('change', details);
  click(byId('refresh-map'), reload);
  click(byId('fit'), () => graph?.fit(undefined, 30));
  click(byId('zoom-in'), () => graph?.zoom(graph.zoom() * 1.18));
  click(byId('zoom-out'), () => graph?.zoom(graph.zoom() / 1.18));
  return async networkId => {
    const snapshot = await api(`/api/v1/networks/${pathId(networkId)}/topology`);
    network = snapshot.network;
    const observations = await api('/api/v1/honeypot/events');
    observed = new Set(observations.filter(event => event.inventory_revision === snapshot.revision
      && network.devices.some(device => device.id === event.inventory_device))
      .map(event => event.inventory_device));
    function markObservations() {
      for (const node of graph.nodes()) node.toggleClass('observed', observed.has(node.id()));
    }
    byId('map-meta').textContent = `${network.name} · Revision ${snapshot.revision}`;
    if (key === snapshot.sha256) { markObservations(); details(); return snapshot; }
    key = snapshot.sha256;
    const previous = select.value;
    select.replaceChildren(...network.devices.map(device => option(device.id, device.name)));
    if (network.devices.some(device => device.id === previous)) select.value = previous;
    graph?.destroy();
    graph = mountGraph(container, elementsFromNetwork(network), 'breadthfirst',
      network.devices.filter(item => item.capabilities.zone_firewall).map(item => `#${item.id}`).join(', ') || undefined);
    markObservations();
    graph.on('tap', 'node', event => {
      if (network.devices.some(item => item.id === event.target.id())) {
        select.value = event.target.id();
        details();
      }
    });
    details();
    return snapshot;
  };
}

export function generatedMermaid(artifact) {
  const lines = artifact.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('%%'));
  if (lines.shift() !== 'flowchart TD' || lines.shift() !== 'hub[Hub]' || lines.length > 32) return null;
  const elements = [{data: {id: 'hub', label: 'Hub'}, classes: 'core'}];
  const seen = new Set();
  for (const line of lines) {
    const match = /^hub --- (site([1-9]\d?))\[Site \2\]$/.exec(line);
    if (!match || seen.has(match[1])) return null;
    seen.add(match[1]);
    elements.push({data: {id: match[1], label: `Site ${match[2]}`}});
    elements.push({data: {id: `hub-${match[1]}`, source: 'hub', target: match[1]}});
  }
  return elements;
}
