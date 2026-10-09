#include <bits/stdc++.h>
using namespace std;
static const long long MOD=998244353;
struct DSU{
    vector<int> p,sz,xr;
    DSU(int n):p(n),sz(n,1),xr(n,0){iota(p.begin(),p.end(),0);}    
    pair<int,int> findp(int x){
        if(p[x]==x) return {x,0};
        auto [r,v]=findp(p[x]);
        xr[x]^=v; p[x]=r;
        return {p[x],xr[x]};
    }
    bool unite(int a,int b,int w){
        auto [ra,xa]=findp(a); auto [rb,xb]=findp(b);
        if(ra==rb) return ((xa^xb)==w);
        if(sz[ra]<sz[rb]){swap(ra,rb); swap(xa,xb);}        
        p[rb]=ra; xr[rb]=xa^xb^w; sz[ra]+=sz[rb];
        return true;
    }
};
long long modpow(long long a,long long e){ long long r=1; while(e){if(e&1)r=r*a%MOD;a=a*a%MOD;e>>=1;} return r; }
int main(){
    ios::sync_with_stdio(false); cin.tie(nullptr);
    int T; if(!(cin>>T)) return 0;
    while(T--){
        int H,W; cin>>H>>W;
        vector<string>S(H); for(auto &s:S) cin>>s;
        DSU dsu(H+W);
        vector<int> col(W,0);
        bool ok=true;
        for(int i=0;i<H;i++){
            int row=0;
            for(int j=0;j<W;j++){
                if(S[i][j]=='B'){
                    int need=1^row^col[j];
                    if(!dsu.unite(i,H+j,need)) ok=false;
                }else{
                    row^=1;
                    col[j]^=1;
                }
            }
            if(row) ok=false;
        }
        for(int j=0;j<W;j++) if(col[j]) ok=false;
        if(!ok){ cout<<0<<'\n'; continue; }
        int comps=0;
        for(int v=0;v<H+W;v++) if(dsu.findp(v).first==v) comps++;
        cout<<modpow(2,comps)<<'\n';
    }
}
