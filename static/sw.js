const CACHE='huntfeed-shell-v1';
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(['/static/style.css','/static/app.js','/static/icon.svg'])));self.skipWaiting()});
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('push',e=>{let d={title:'HuntFeed threat alert',body:'New report available',url:'/'};try{d={...d,...e.data.json()}}catch{}e.waitUntil(self.registration.showNotification(d.title,{body:d.body,icon:'/static/icon.svg',badge:'/static/icon.svg',tag:'huntfeed-new-'+d.url,data:{url:d.url}}))});
self.addEventListener('notificationclick',e=>{e.notification.close();const url=new URL(e.notification.data?.url||'/',self.location.origin).href;e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(cs=>{const c=cs.find(x=>x.url.startsWith(self.location.origin));if(c){c.navigate(url);return c.focus()}return self.clients.openWindow(url)}))});
