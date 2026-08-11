#include <bits/stdc++.h>
using namespace std;
using int64 = long long;
const long long MOD = 998244353;

struct Comp{
    long long lo, hi;
    long long cnt;
};

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N; cin >> N;
    vector<long long>A(N);
    for(auto &x:A) cin >> x;

    vector<Comp> c;
    c.push_back({0,0,1});

    for(long long a:A){
        vector<Comp> v;
        v.reserve(c.size()*2);
        for(auto z:c){
            v.push_back(z);
            v.push_back({z.lo+a,z.hi+a,z.cnt});
        }
        sort(v.begin(),v.end(),[](const Comp&x,const Comp&y){
            if(x.lo!=y.lo) return x.lo<y.lo;
            return x.hi<y.hi;
        });

        vector<Comp> nc;
        nc.reserve(v.size());
        for(auto z:v){
            if(nc.empty()){
                nc.push_back(z);
                continue;
            }
            auto &p=nc.back();
            bool connected;
            if(z.lo<=p.hi) connected=true;
            else connected = (__int128)101*p.hi > (__int128)100*z.lo;
            if(connected){
                p.hi=max(p.hi,z.hi);
                p.cnt += z.cnt;
                if(p.cnt>=MOD) p.cnt-=MOD;
            }else{
                nc.push_back(z);
            }
        }
        c.swap(nc);
    }

    cout << (int)c.size()-1 << '\n';
    long long pref=0;
    for(size_t i=0;i+1<c.size();i++){
        pref += c[i].cnt;
        pref %= MOD;
        cout << c[i].hi << ' ' << c[i+1].lo << ' ' << pref << '\n';
    }
    return 0;
}
