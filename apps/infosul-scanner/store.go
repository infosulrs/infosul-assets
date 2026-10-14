package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Favorite é um item da aba Favoritos (o original identifica por IP + MAC).
type Favorite struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	Name    string `json:"name"`
	Comment string `json:"comment"`
}

// Meta guarda nome e comentário editados pelo técnico para um host.
type Meta struct {
	Name    string `json:"name"`
	Comment string `json:"comment"`
}

type storeData struct {
	Options   Options         `json:"options"`
	Favorites []Favorite      `json:"favorites"`
	Meta      map[string]Meta `json:"meta"` // chave: MAC (ou IP quando não há MAC)
	MRU       []string        `json:"mru"`
}

// Store é persistido em dados.json na pasta de dados do usuário.
type Store struct {
	mu   sync.Mutex
	path string
	d    storeData
}

func OpenStore() *Store {
	s := &Store{path: filepath.Join(dataDir(), "dados.json")}
	s.d.Options = DefaultOptions()
	if b, err := os.ReadFile(s.path); err == nil {
		json.Unmarshal(b, &s.d)
	}
	s.d.Options.normalize()
	if s.d.Meta == nil {
		s.d.Meta = map[string]Meta{}
	}
	return s
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s.d, "", "  ")
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func metaKey(ip, mac string) string {
	if mac != "" {
		return strings.ToUpper(mac)
	}
	return ip
}

func (s *Store) Snapshot() storeData {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.d
	d.Favorites = append([]Favorite(nil), s.d.Favorites...)
	d.MRU = append([]string(nil), s.d.MRU...)
	d.Meta = make(map[string]Meta, len(s.d.Meta))
	for k, v := range s.d.Meta {
		d.Meta[k] = v
	}
	return d
}

func (s *Store) SetOptions(o Options) error {
	o.normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.Options = o
	return s.saveLocked()
}

func (s *Store) AddMRU(r string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := []string{r}
	for _, x := range s.d.MRU {
		if x != r && len(list) < 15 {
			list = append(list, x)
		}
	}
	s.d.MRU = list
	s.saveLocked()
}

func (s *Store) SetMeta(ip, mac string, m Meta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := metaKey(ip, mac)
	if m.Name == "" && m.Comment == "" {
		delete(s.d.Meta, k)
	} else {
		s.d.Meta[k] = m
	}
	for i, f := range s.d.Favorites {
		if f.IP == ip && strings.EqualFold(f.MAC, mac) {
			s.d.Favorites[i].Name, s.d.Favorites[i].Comment = m.Name, m.Comment
		}
	}
	return s.saveLocked()
}

func (s *Store) AddFavorite(f Favorite) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.d.Favorites {
		if x.IP == f.IP && strings.EqualFold(x.MAC, f.MAC) {
			s.d.Favorites[i] = f
			return s.saveLocked()
		}
	}
	s.d.Favorites = append(s.d.Favorites, f)
	return s.saveLocked()
}

func (s *Store) RemoveFavorite(ip, mac string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.d.Favorites[:0]
	for _, x := range s.d.Favorites {
		if !(x.IP == ip && strings.EqualFold(x.MAC, mac)) {
			out = append(out, x)
		}
	}
	s.d.Favorites = out
	return s.saveLocked()
}

// ClearData corresponde a "Excluir dados armazenados" no original.
func (s *Store) ClearData() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.Meta = map[string]Meta{}
	s.d.MRU = nil
	return s.saveLocked()
}
