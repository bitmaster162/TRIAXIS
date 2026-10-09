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

        int V=H*W*4;
        vector<int> dist(V,INF);
        deque<int> dq;
        auto id=[&](int r,int c,int d){ return ((r*W+c)*4+d); };

        for(int d=0;d<4;d++){
            int nr=dr[d], nc=dc[d];
            if(0<=nr && nr<H && 0<=nc && nc<W){
                int w=(S[nr][nc]=='#');
                int v=id(nr,nc,d);
                if(w<dist[v]){
                    dist[v]=w;
                    if(w) dq.push_back(v);
                    else dq.push_front(v);
                }
            }
        }

        while(!dq.empty()){
            int v=dq.front(); dq.pop_front();
            int d=v%4;
            int cell=v/4;
            int r=cell/W, c=cell%W;
            int cur=dist[v];

            for(int nd=0;nd<4;nd++){
                if(nd==d) continue;
                int nr=r+dr[nd], nc=c+dc[nd];
                if(nr<0||nr>=H||nc<0||nc>=W) continue;
                int w=(S[nr][nc]=='#');
                int to=id(nr,nc,nd);
                if(cur+w<dist[to]){
                    dist[to]=cur+w;
                    if(w) dq.push_back(to);
                    else dq.push_front(to);
                }
            }
        }

        int ans=INF;
        for(int d=0;d<4;d++) ans=min(ans,dist[id(H-1,W-1,d)]);
        cout << ans << '\n';
    }
    return 0;
}
