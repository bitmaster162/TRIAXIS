#include <bits/stdc++.h>
using namespace std;
using u64 = unsigned long long;
using i64 = long long;

static int pcpar(u64 x){ return __builtin_parityll(x); }

// Sum_{0 <= x < n} (-1)^{popcount(x)}.
static i64 pref_diff(u64 n){
    if((n & 1ULL) == 0) return 0;
    return pcpar(n >> 1) ? -1 : 1;
}

static bool connected_interval(u64 L, u64 R){
    if(L == R) return true;
    u64 z = L ^ R;
    int h = 63 - __builtin_clzll(z);
    return (R - L) >= (1ULL << h);
}

static vector<pair<u64,u64>> components(u64 L, u64 R){
    vector<pair<u64,u64>> out;
    vector<pair<u64,u64>> st{{L,R}};
    while(!st.empty()){
        auto [l,r]=st.back(); st.pop_back();
        if(connected_interval(l,r)){
            out.push_back({l,r});
            continue;
        }
        int h = 63 - __builtin_clzll(l ^ r);
        u64 block = (l >> (h+1)) << (h+1);
        u64 mid = block + (1ULL << h);
        st.push_back({mid,r});
        st.push_back({l,mid-1});
    }
    sort(out.begin(),out.end());
    return out;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int T; cin >> T;
    while(T--){
        int q;
        u64 L,R;
        cin >> q >> L >> R;
        auto comps = components(L,R);
        u64 best = 0;
        vector<int> choose;
        choose.reserve(comps.size());

        for(auto [l,r]: comps){
            u64 len = r-l+1;
            i64 d = pref_diff(r+1) - pref_diff(l);
            u64 even_cnt = (u64)((i64)len + d) / 2;
            u64 odd_cnt  = len - even_cnt;
            if(even_cnt >= odd_cnt){
                best += even_cnt;
                choose.push_back(0);
            }else{
                best += odd_cnt;
                choose.push_back(1);
            }
        }

        if(q==0){
            cout << best << '\n';
        }else{
            string ans((size_t)(R-L+1),'0');
            for(size_t ci=0; ci<comps.size(); ++ci){
                auto [l,r]=comps[ci];
                int p=choose[ci];
                for(u64 x=l;;++x){
                    if(pcpar(x)==p) ans[(size_t)(x-L)]='1';
                    if(x==r) break;
                }
            }
            cout << ans << '\n';
        }
    }
    return 0;
}
