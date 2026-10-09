#include <bits/stdc++.h>
using namespace std;
static const long long MOD=998244353;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    if(!(cin>>N)) return 0;
    vector<int> y(N+2);
    y[0]=N+1; y[N+1]=0;
    vector<pair<int,int>> pts(N);
    for(int i=0;i<N;i++){
        int x,yy; cin>>x>>yy;
        pts[i]={x,yy};
    }
    sort(pts.begin(),pts.end());
    for(auto [x,yy]:pts) y[x]=yy;

    vector<vector<int>> ps(N+1, vector<int>(N+1,0));
    for(int x=1;x<=N;x++) ps[x][y[x]]=1;
    for(int x=1;x<=N;x++) for(int yy=1;yy<=N;yy++)
        ps[x][yy]+=ps[x-1][yy]+ps[x][yy-1]-ps[x-1][yy-1];

    auto rect=[&](int xl,int xr,int yl,int yr)->int{
        if(xl>xr || yl>yr) return 0;
        xl=max(xl,1); xr=min(xr,N);
        yl=max(yl,1); yr=min(yr,N);
        if(xl>xr || yl>yr) return 0;
        return ps[xr][yr]-ps[xl-1][yr]-ps[xr][yl-1]+ps[xl-1][yl-1];
    };
    auto essential=[&](int a,int b,int c)->bool{
        int q1=rect(a+1,b-1,y[c]+1,y[b]-1);
        int q2=rect(b+1,c-1,y[b]+1,y[a]-1);
        return q1+q2>0;
    };

    vector<vector<long long>> dp(N+1, vector<long long>(N+1,0));
    for(int b=1;b<=N;b++) dp[0][b]=1;

    for(int a=0;a<=N;a++){
        for(int b=max(1,a+1);b<=N;b++){
            long long cur=dp[a][b];
            if(!cur) continue;
            if(!(y[a]>y[b])) continue;
            for(int c=b+1;c<=N;c++){
                if(y[b]>y[c] && essential(a,b,c)){
                    dp[b][c]+=cur;
                    if(dp[b][c]>=MOD) dp[b][c]-=MOD;
                }
            }
        }
    }

    long long ans=1; // empty selected set -> all balls remain
    for(int a=0;a<=N;a++){
        for(int b=max(1,a+1);b<=N;b++){
            if(dp[a][b] && y[a]>y[b] && essential(a,b,N+1)){
                ans+=dp[a][b];
                if(ans>=MOD) ans-=MOD;
            }
        }
    }
    cout<<ans%MOD<<'\n';
    return 0;
}
