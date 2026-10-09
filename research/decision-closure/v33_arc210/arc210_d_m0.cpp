#include <bits/stdc++.h>
using namespace std;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int T; cin >> T;
    while(T--){
        int N,M; cin >> N >> M;
        vector<vector<int>> g(N);
        vector<int> deg(N);
        for(int i=0;i<M;i++){
            int u,v; cin >> u >> v; --u;--v;
            g[u].push_back(v); g[v].push_back(u);
            deg[u]++; deg[v]++;
        }

        bool alice=false;
        if(N&1){
            alice=true;
            for(int d:deg) if(d>1){ alice=false; break; }
        }else{
            vector<int> high, two;
            for(int v=0;v<N;v++){
                if(deg[v]>=3) high.push_back(v);
                if(deg[v]==2) two.push_back(v);
            }
            if(high.size()>=2){
                alice=false;
            }else if(high.size()==1){
                int r=high[0];
                vector<char> adj(N,false);
                for(int u:g[r]) adj[u]=true;
                alice=true;
                for(int u=0;u<N;u++) if(u!=r){
                    int ed=deg[u]-(adj[u]?1:0);
                    if(ed>1){ alice=false; break; }
                }
            }else if(two.empty()){
                alice=true;
            }else{
                int u=two[0];
                vector<int> cand={u};
                for(int v:g[u]) cand.push_back(v);
                sort(cand.begin(),cand.end());
                cand.erase(unique(cand.begin(),cand.end()),cand.end());
                for(int r:cand){
                    vector<char> adj(N,false);
                    for(int v:g[r]) adj[v]=true;
                    bool ok=true;
                    for(int x=0;x<N;x++) if(x!=r){
                        int ed=deg[x]-(adj[x]?1:0);
                        if(ed>1){ ok=false; break; }
                    }
                    if(ok){ alice=true; break; }
                }
            }
        }
        cout << (alice ? "Alice" : "Bob") << '\n';
    }
    return 0;
}
