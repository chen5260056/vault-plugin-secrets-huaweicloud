package huaweicloud

import "testing"

func assertErrorNotNil(t *testing.T,err error){
    t.Helper()
    t.Helper()
    if err != nil {
        t.Fatalf("\nunexpected error: %s", err)
    }
}
