#include <bits/stdc++.h>
using namespace std;
struct DSU{
    vector<int> p,sz;
    DSU(int n):p(n),sz(n,1){iota(p.begin(),p.end(),0);}    
    int find(int x){return p[x]==x?x:p[x]=find(p[x]);}
    void unite(int a,int b){a=find(a);b=find(b);if(a==b)return;if(sz[a]<sz[b])swap(a,b);p[b]=a;sz[a]+=sz[b];}
};
int main(){
    ios::sync_with_stdio(false); cin.tie(nullptr);
    int N,M,Q; if(!(cin>>N>>M>>Q)) return 0;
    vector<int>S(M),T(M);
    for(int i=0;i<M;i++) cin>>S[i]>>T[i],--S[i],--T[i];
    while(Q--){
        int L,R; cin>>L>>R; --L;--R;
        DSU dsu(N);
        for(int i=L;i<=R;i++) dsu.unite(S[i],T[i]);
        vector<vector<int>> g(N);
        vector<int> indeg(N,0);
        bool ok=true;
        for(int i=L;i<=R && ok;i++){
            int a=S[i], b=T[i], l=min(a,b), r=max(a,b);
            int ep=dsu.find(a);
            for(int k=l+1;k<r;k++){
                int x=dsu.find(k);
                if(x==ep){ ok=false; break; }
                if(a<b) g[ep].push_back(x);
                else    g[x].push_back(ep);
            }
        }
        if(ok){
            for(int u=0;u<N;u++) if(dsu.find(u)==u){
                sort(g[u].begin(),g[u].end());
                g[u].erase(unique(g[u].begin(),g[u].end()),g[u].end());
                for(int v:g[u]) indeg[v]++;
            }
            queue<int> qu; int roots=0,seen=0;
            for(int u=0;u<N;u++) if(dsu.find(u)==u){ roots++; if(indeg[u]==0) qu.push(u); }
            while(!qu.empty()){
                int u=qu.front();qu.pop();seen++;
                for(int v:g[u]) if(--indeg[v]==0) qu.push(v);
            }
            ok=(seen==roots);
        }
        cout<<(ok?"Yes":"No")<<'\n';
    }
}
