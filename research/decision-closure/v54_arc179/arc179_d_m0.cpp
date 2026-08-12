#include <bits/stdc++.h>
using namespace std;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    if(!(cin>>N)) return 0;
    vector<vector<int>> g(N);
    vector<int> deg(N,0);
    for(int i=0;i<N-1;i++){
        int u,v; cin>>u>>v; --u;--v;
        g[u].push_back(v);
        g[v].push_back(u);
        deg[u]++; deg[v]++;
    }

    vector<char> important(N,0), removed(N,0);
    int B=0;
    for(int v=0;v<N;v++){
        if(deg[v]>=3){
            important[v]=1;
            B++;
        }
    }

    if(B<=1){
        cout << N-1 << '\n';
        return 0;
    }

    vector<int> curdeg=deg;
    queue<int> q;
    for(int v=0;v<N;v++){
        if(!important[v] && curdeg[v]<=1) q.push(v);
    }
    while(!q.empty()){
        int v=q.front(); q.pop();
        if(removed[v] || important[v] || curdeg[v]>1) continue;
        removed[v]=1;
        for(int to:g[v]){
            if(removed[to]) continue;
            --curdeg[to];
            if(!important[to] && curdeg[to]<=1) q.push(to);
        }
        curdeg[v]=0;
    }

    int L=0;
    for(int v=0;v<N;v++){
        if(important[v] && curdeg[v]<=1) L++;
    }

    long long ans=(long long)N-1 + max(0,L-2);
    cout << ans << '\n';
    return 0;
}
