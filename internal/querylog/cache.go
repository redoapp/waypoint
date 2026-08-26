package querylog

import (
	"container/list"
	"sync"
)

// defaultCacheSize bounds the number of memoized statement analyses. Parsing
// dominates the cost of a query log record, and real workloads repeat a small
// set of statement texts, so a modest cache turns almost every lookup into a
// map hit.
const defaultCacheSize = 1024

// maxCacheableStatement keeps pathological one-off statements (generated
// multi-megabyte INSERTs, for instance) from evicting the working set.
const maxCacheableStatement = 8 * 1024

var analysisCache = newMetaCache(defaultCacheSize)

// metaCache is a bounded LRU keyed by raw statement text.
type metaCache struct {
	mu    sync.Mutex
	max   int
	ll    *list.List // front = most recently used
	items map[string]*list.Element
}

type cacheEntry struct {
	key  string
	meta SQLMeta
}

func newMetaCache(max int) *metaCache {
	return &metaCache{
		max:   max,
		ll:    list.New(),
		items: make(map[string]*list.Element, max),
	}
}

func (c *metaCache) get(key string) (SQLMeta, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return SQLMeta{}, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*cacheEntry).meta, true
}

func (c *metaCache) put(key string, meta SQLMeta) {
	if len(key) > maxCacheableStatement {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		el.Value.(*cacheEntry).meta = meta
		c.ll.MoveToFront(el)
		return
	}

	c.items[key] = c.ll.PushFront(&cacheEntry{key: key, meta: meta})

	for c.ll.Len() > c.max {
		oldest := c.ll.Back()
		if oldest == nil {
			break
		}
		c.ll.Remove(oldest)
		delete(c.items, oldest.Value.(*cacheEntry).key)
	}
}

func (c *metaCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
