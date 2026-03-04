package kernel

import "sync"

// Kernel manages the route → PolicyChain mapping.
// All public methods are goroutine-safe.
type Kernel struct {
	mu     sync.RWMutex
	routes map[string]*PolicyChain
}

// NewKernel returns an empty Kernel.
func NewKernel() *Kernel {
	return &Kernel{routes: make(map[string]*PolicyChain)}
}

// RegisterRoute associates a PolicyChain with an Envoy route name.
func (k *Kernel) RegisterRoute(routeName string, chain *PolicyChain) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.routes[routeName] = chain
}

// GetChain returns the PolicyChain for the given route name, or nil if none is registered.
func (k *Kernel) GetChain(routeName string) *PolicyChain {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.routes[routeName]
}
