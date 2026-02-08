const CACHE_NAME = 'vault-admin-v1'
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icons/icon-192x192.png',
  '/icons/icon-512x512.png',
]

// Install event - cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS)
    })
  )
  self.skipWaiting()
})

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      )
    })
  )
  self.clients.claim()
})

// Fetch event - serve from cache, fallback to network
self.addEventListener('fetch', (event) => {
  const { request } = event
  const url = new URL(request.url)

  // Skip non-GET requests
  if (request.method !== 'GET') return

  // Skip API requests
  if (url.pathname.startsWith('/api/')) return

  // Skip external requests
  if (url.origin !== self.location.origin) return

  event.respondWith(
    caches.match(request).then((response) => {
      if (response) {
        return response
      }

      return fetch(request)
        .then((networkResponse) => {
          // Don't cache if not successful
          if (!networkResponse || networkResponse.status !== 200) {
            return networkResponse
          }

          // Clone the response
          const responseToCache = networkResponse.clone()

          // Cache the fetched response
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(request, responseToCache)
          })

          return networkResponse
        })
        .catch(() => {
          // Fallback for HTML pages
          if (request.headers.get('accept').includes('text/html')) {
            return caches.match('/index.html')
          }
          return new Response('Network error', { status: 408 })
        })
    })
  )
})

// Background sync for offline form submissions
self.addEventListener('sync', (event) => {
  if (event.tag === 'sync-forms') {
    event.waitUntil(syncFormSubmissions())
  }
})

// Push notifications
self.addEventListener('push', (event) => {
  const data = event.data.json()
  
  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/icons/icon-192x192.png',
      badge: '/icons/icon-72x72.png',
      tag: data.tag,
      data: data.data,
      actions: data.actions || [],
    })
  )
})

// Notification click
self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  
  event.waitUntil(
    clients.openWindow(event.notification.data?.url || '/')
  )
})

async function syncFormSubmissions() {
  // Get stored form submissions from IndexedDB
  const db = await openDB('vault-offline', 1)
  const submissions = await db.getAll('formSubmissions')
  
  for (const submission of submissions) {
    try {
      await fetch(submission.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(submission.data),
      })
      
      // Remove from queue on success
      await db.delete('formSubmissions', submission.id)
    } catch (error) {
      console.error('Failed to sync submission:', error)
    }
  }
}

// Helper for IndexedDB
function openDB(name, version) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, version)
    
    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result)
    
    request.onupgradeneeded = (event) => {
      const db = event.target.result
      if (!db.objectStoreNames.contains('formSubmissions')) {
        db.createObjectStore('formSubmissions', { keyPath: 'id', autoIncrement: true })
      }
    }
  })
}
