#include <bits/stdc++.h>
using namespace std;

static vector<pair<int,int>> round_pairs(int m, int r){
    vector<pair<int,int>> e;
    int q=m-1;
    e.push_back({m-1,r});
    for(int k=1;k<m/2;k++){
        int a=(r+k)%q;
        int b=(r-k)%q; if(b<0) b+=q;
        e.push_back({a,b});
    }
    return e;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int T; cin>>T;
    while(T--){
        int N; cin>>N;
        vector<int> Y(N);
        for(int &x:Y){cin>>x; --x;}
        bool ok=true;
        for(int i=0;i<N;i++){
            if(Y[i]<0 || Y[i]>=N || Y[Y[i]]!=i){ ok=false; break; }
        }
        vector<int> fixed;
        if(ok) for(int i=0;i<N;i++) if(Y[i]==i) fixed.push_back(i);
        if(ok && (N&1) && (int)fixed.size()!=1) ok=false;
        if(!ok){
            cout<<"No\n";
            continue;
        }
        if(N==1){
            cout<<"Yes\n1\n";
            continue;
        }
        int m = (N&1) ? N+1 : N;
        int ghost = (N&1) ? N : -1;
        vector<pair<int,int>> target;
        vector<pair<int,int>> fixed_pairs;
        vector<char> used(N,false);
        for(int i=0;i<N;i++){
            if(Y[i]!=i && i<Y[i]){
                target.push_back({i,Y[i]});
                used[i]=used[Y[i]]=true;
            }
        }
        if(N&1){
            target.push_back({fixed[0],ghost});
        }else{
            for(int k=0;k<(int)fixed.size();k+=2){
                target.push_back({fixed[k],fixed[k+1]});
                fixed_pairs.push_back({fixed[k],fixed[k+1]});
            }
        }
        if((int)target.size()!=m/2){
            cout<<"No\n";
            continue;
        }
        auto std0=round_pairs(m,0);
        vector<int> phi(m,-1);
        for(int k=0;k<m/2;k++){
            phi[std0[k].first]=target[k].first;
            phi[std0[k].second]=target[k].second;
        }
        vector<vector<int>> A(N, vector<int>(N,0));
        if(!(N&1)){
            for(int i=0;i<N;i++) A[i][i]=N;
        }
        for(int r=0;r<m-1;r++){
            int color=r+1;
            for(auto [a,b]: round_pairs(m,r)){
                int u=phi[a], v=phi[b];
                if(N&1 && (u==ghost || v==ghost)){
                    int w=(u==ghost?v:u);
                    A[w][w]=color;
                }else{
                    A[u][v]=A[v][u]=color;
                }
            }
        }
        if(!(N&1)){
            for(auto [u,v]: fixed_pairs){
                A[u][u]=1;
                A[v][v]=1;
                A[u][v]=A[v][u]=N;
            }
        }
        for(int i=0;i<N && ok;i++){
            vector<int> seen(N+1,0);
            for(int j=0;j<N;j++){
                if(A[i][j]<1 || A[i][j]>N || seen[A[i][j]]) {ok=false; break;}
                seen[A[i][j]]=1;
                if(A[i][j]!=A[j][i]) {ok=false; break;}
            }
            if(A[i][Y[i]]!=1) ok=false;
        }
        if(!ok){
            cout<<"No\n";
        }else{
            cout<<"Yes\n";
            for(int i=0;i<N;i++){
                for(int j=0;j<N;j++){
                    if(j) cout<<' ';
                    cout<<A[i][j];
                }
                cout<<'\n';
            }
        }
    }
    return 0;
}
