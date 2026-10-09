#include <bits/stdc++.h>
using namespace std;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int T;
    cin >> T;
    const int INF = 1e9;
    const int dr[4]={-1,1,0,0};
    const int dc[4]={0,0,-1,1};

    while(T--){
        int H,W;
        cin >> H >> W;
        vector<string> S(H);
        for(auto &s:S) cin >> s;

        auto inside=[&](int r,int c){ return 0<=r && r<H && 0<=c && c<W; };
        auto wall=[&](int r,int c){ return S[r][c]=='#' ? 1 : 0; };
        auto id=[&](int r,int c,int d){ return ((r*W+c)*4+d); };

        int V=H*W*4;
        vector<int> dist(V,INF);
        priority_queue<pair<int,int>, vector<pair<int,int>>, greater<pair<int,int>>> pq;

        for(int d=0;d<4;d++){
            int nr=dr[d], nc=dc[d];
            if(inside(nr,nc)){
                int v=id(nr,nc,d);
                int w=wall(nr,nc);
                if(w<dist[v]){
                    dist[v]=w;
                    pq.push({w,v});
                }
            }
        }

        while(!pq.empty()){
            auto [du,v]=pq.top(); pq.pop();
            if(du!=dist[v]) continue;
            int d=v%4;
            int cell=v/4;
            int r=cell/W, c=cell%W;

            for(int nd=0;nd<4;nd++){
                int nr=r+dr[nd], nc=c+dc[nd];
                if(!inside(nr,nc)) continue;

                int extra=wall(nr,nc);
                if(nd==d){
                    int bestSide=INF;
                    if(d<2){
                        for(int p: {2,3}){
                            int sr=r+dr[p], sc=c+dc[p];
                            if(inside(sr,sc)) bestSide=min(bestSide,wall(sr,sc));
                        }
                    }else{
                        for(int p: {0,1}){
                            int sr=r+dr[p], sc=c+dc[p];
                            if(inside(sr,sc)) bestSide=min(bestSide,wall(sr,sc));
                        }
                    }
                    if(bestSide==INF) continue;
                    extra += bestSide;
                }

                int to=id(nr,nc,nd);
                if(du+extra<dist[to]){
                    dist[to]=du+extra;
                    pq.push({dist[to],to});
                }
            }
        }

        int ans=INF;
        for(int d=0;d<4;d++) ans=min(ans,dist[id(H-1,W-1,d)]);
        cout << ans << '\n';
    }
    return 0;
}
