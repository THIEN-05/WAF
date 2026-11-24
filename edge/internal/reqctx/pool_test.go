package reqctx

import (
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/example/wafplatform/pkg/wafcore"
)

// Connection-scoped values are explicitly allowed to be carried between the
// transport and request context, but Release currently clears those as well.
// Keeping this empty means a future field is never silently exempted.
var requestCtxConnectionFieldExemptions = map[string]bool{}

func TestReleaseZerosEveryRequestCtxField(t *testing.T) {
	c := &RequestCtx{}
	v := reflect.ValueOf(c).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if err := dirtyRequestCtxField(field, i+1); err != nil {
			t.Fatalf("cannot dirty field %s: %v", v.Type().Field(i).Name, err)
		}
	}
	Release(c)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if requestCtxConnectionFieldExemptions[name] {
			continue
		}
		if !v.Field(i).IsZero() {
			t.Errorf("Release left RequestCtx.%s non-zero: %#v", name, v.Field(i).Interface())
		}
	}
	if len(requestCtxConnectionFieldExemptions) != 0 {
		t.Fatalf("connection field exemptions require an explicit reset contract: %v", requestCtxConnectionFieldExemptions)
	}
}

func dirtyRequestCtxField(v reflect.Value, seed int) error {
	if !v.CanSet() {
		return nil
	}
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.String:
		v.SetString("dirty-" + strconv.Itoa(seed))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(seed))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		v.SetUint(uint64(seed))
	case reflect.Float32, reflect.Float64:
		v.SetFloat(float64(seed))
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
	case reflect.Interface:
		switch {
		case v.Type().NumMethod() == 0:
			v.Set(reflect.ValueOf(fmt.Sprintf("dirty-%d", seed)))
		case v.Type().Implements(reflect.TypeOf((*error)(nil)).Elem()):
			v.Set(reflect.ValueOf(errors.New("dirty error")))
		default:
			return fmt.Errorf("unsupported interface %s", v.Type())
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		if v.Type().Elem().Kind() == reflect.Uint8 {
			v.Index(0).SetUint(uint64(byte(seed)))
		} else if err := dirtyRequestCtxField(v.Index(0), seed+1); err != nil {
			return err
		}
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		key := reflect.New(v.Type().Key()).Elem()
		if err := dirtyRequestCtxField(key, seed+1); err != nil {
			return err
		}
		value := reflect.New(v.Type().Elem()).Elem()
		if err := dirtyRequestCtxField(value, seed+2); err != nil {
			return err
		}
		v.SetMapIndex(key, value)
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			v.Set(reflect.ValueOf(time.Unix(int64(seed), 1)))
			return nil
		}
		for i := 0; i < v.NumField(); i++ {
			if err := dirtyRequestCtxField(v.Field(i), seed+i+1); err != nil {
				return err
			}
		}
		if v.IsZero() {
			return fmt.Errorf("struct %s has no reflectively writable non-zero field", v.Type())
		}
	case reflect.Array:
		if v.Len() == 0 {
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := dirtyRequestCtxField(v.Index(i), seed+i+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported field kind %s", v.Kind())
	}
	return nil
}

func TestConcurrentRequestCtxPoolDoesNotShareRequestData(t *testing.T) {
	const workers, rounds = 40, 200
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for round := 0; round < rounds; round++ {
				id := fmt.Sprintf("%d-%d", worker, round)
				r := httptest.NewRequest("GET", "http://site.test/"+id, nil)
				ctx := New(r, &wafcore.Snapshot{}, id, net.ParseIP("192.0.2.1"))
				if ctx.RequestID != id || ctx.Path != "/"+id || ctx.queryParsed || ctx.bodyLoaded || len(ctx.tags) != 0 {
					errs <- fmt.Errorf("worker %d round %d received stale request state", worker, round)
					Release(ctx)
					return
				}
				ctx.BotChallengeToken = id
				ctx.AddTag(id)
				ctx.QueryValues()
				Release(ctx)
			}
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	runtime.GC()
}

type testFingerprint string

func (f testFingerprint) Fingerprint() (string, string) { return string(f), "ja4-after-reset" }

func TestNewAppliesFingerprintAfterReset(t *testing.T) {
	c := &RequestCtx{JA3: "stale-ja3", JA4: "stale-ja4", RequestID: "stale", queryParsed: true}
	pool.Put(c)
	r := httptest.NewRequest("GET", "http://site.test/", nil)
	r = r.WithContext(WithFingerprintSource(r.Context(), testFingerprint("fresh-ja3")))
	got := New(r, nil, "fresh-id", nil)
	defer Release(got)
	if got.JA3 != "fresh-ja3" || got.JA4 != "ja4-after-reset" || got.RequestID != "fresh-id" || got.queryParsed {
		t.Fatalf("New did not reset then attach fingerprint: %+v", got)
	}
}
