#include <bits/stdc++.h>
using namespace std;
using ll = long long;
const ll INF = (1LL<<62);

struct MCMF {
    struct E { int to, rev, cap; ll cost; };
    int n;
    vector<vector<E>> g;
    MCMF(int n):n(n),g(n){}
    void addEdge(int s,int t,int cap,ll cost){
        E a{t,(int)g[t].size(),cap,cost};
        E b{s,(int)g[s].size(),0,-cost};
        g[s].push_back(a); g[t].push_back(b);
    }
    pair<int,ll> mincost(int s,int t,int need){
        vector<ll> pot(n,0), dist(n);
        vector<int> pv(n), pe(n);
        int flow=0; ll cost=0;
        while(flow<need){
            fill(dist.begin(),dist.end(),INF);
            dist[s]=0;
            priority_queue<pair<ll,int>,vector<pair<ll,int>>,greater<pair<ll,int>>> pq;
            pq.push({0,s});
            while(!pq.empty()){
                auto [d,v]=pq.top(); pq.pop();
                if(d!=dist[v]) continue;
                for(int i=0;i<(int)g[v].size();++i){
                    auto const &e=g[v][i];
                    if(!e.cap) continue;
                    ll nd=d+e.cost+pot[v]-pot[e.to];
                    if(nd<dist[e.to]){
                        dist[e.to]=nd; pv[e.to]=v; pe[e.to]=i;
                        pq.push({nd,e.to});
                    }
                }
            }
            if(dist[t]==INF) break;
            for(int v=0;v<n;++v) if(dist[v]<INF) pot[v]+=dist[v];
            int add=need-flow;
            for(int v=t;v!=s;v=pv[v]) add=min(add,g[pv[v]][pe[v]].cap);
            for(int v=t;v!=s;v=pv[v]){
                auto &e=g[pv[v]][pe[v]];
                cost += (ll)add*e.cost;
                e.cap-=add;
                g[v][e.rev].cap+=add;
            }
            flow+=add;
        }
        return {flow,cost};
    }
};

static vector<int> branch_labels(const vector<vector<int>>& g, int k){
    int n=g.size();
    vector<int> lab(n,-1);
    int id=0;
    for(int nb:g[k]){
        stack<int> st;
        st.push(nb);
        lab[nb]=id;
        while(!st.empty()){
            int v=st.top(); st.pop();
            for(int to:g[v]){
                if(to==k || lab[to]!=-1) continue;
                lab[to]=id;
                st.push(to);
            }
        }
        ++id;
    }
    return lab;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int tc; cin>>tc;
    while(tc--){
        int N; cin>>N;
        vector<ll>A(N);
        for(auto &x:A) cin>>x;
        vector<vector<int>> T(N),U(N);
        for(int i=0;i<N-1;++i){
            int a,b;cin>>a>>b;--a;--b;
            T[a].push_back(b);T[b].push_back(a);
        }
        for(int i=0;i<N-1;++i){
            int a,b;cin>>a>>b;--a;--b;
            U[a].push_back(b);U[b].push_back(a);
        }
        for(int k=0;k<N;++k){
            if(k) cout << ' ';
            if((int)T[k].size()<4 || (int)U[k].size()<4){
                cout << -1;
                continue;
            }
            auto lt=branch_labels(T,k);
            auto lu=branch_labels(U,k);
            int dT=T[k].size(), dU=U[k].size();
            int S=dT+dU, Z=S+1;
            MCMF mf(Z+1);
            for(int i=0;i<dT;++i) mf.addEdge(S,i,1,0);
            for(int j=0;j<dU;++j) mf.addEdge(dT+j,Z,1,0);
            for(int x=0;x<N;++x) if(x!=k){
                mf.addEdge(lt[x],dT+lu[x],1,A[x]);
            }
            auto [f,cost]=mf.mincost(S,Z,4);
            cout << (f==4?cost:-1);
        }
        cout << '\n';
    }
    return 0;
}
