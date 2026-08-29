#include <bits/stdc++.h>
using namespace std;
struct DSU{
    vector<int> p,sz,xr;
    DSU(int n):p(n),sz(n,1),xr(n){ iota(p.begin(),p.end(),0); }
    pair<int,int> findp(int x){
        if(p[x]==x) return {x,0};
        auto [r,v]=findp(p[x]);
        xr[x]^=v; p[x]=r;
        return {p[x],xr[x]};
    }
    bool unite(int a,int b,int w){
        auto [ra,xa]=findp(a); auto [rb,xb]=findp(b);
        if(ra==rb) return ((xa^xb)==w);
        if(sz[ra]<sz[rb]){ swap(ra,rb); swap(xa,xb); }
        p[rb]=ra; xr[rb]=xa^xb^w; sz[ra]+=sz[rb];
        return true;
    }
};
int main(){
    ios::sync_with_stdio(false); cin.tie(nullptr);
    int N,M; if(!(cin>>N>>M)) return 0;
    DSU d(2*N);
    bool ok=true;
    for(int i=0;i<M;i++){
        int A,B,C; cin>>A>>B>>C; --A;--B;
        // Y_A xor L_B = C. Y nodes [0,N), L nodes [N,2N).
        if(ok && !d.unite(A,N+B,C)) ok=false;
    }
    if(!ok){ cout<<-1<<"\n"; return 0; }
    vector<int> val(2*N);
    for(int i=0;i<2*N;i++){
        auto [r,x]=d.findp(i); val[i]=x; // root value chosen 0
    }
    string ans(N,'0');
    for(int i=0;i<N;i++) ans[i]=char('0'+(val[i]^val[N+i]));
    cout<<ans<<"\n";
}
