#include <bits/stdc++.h>
using namespace std;

static int mex2(int x,int y){
    for(int z=0;;z++) if(z!=x && z!=y) return z;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N;
    if(!(cin>>N)) return 0;
    vector<int>P(N);
    for(int&i:P){cin>>i;--i;}
    int Q;cin>>Q;
    while(Q--){
        int A0,A1,A2; cin>>A0>>A1>>A2;
        vector<int>B(N,-1);
        long long best=LLONG_MIN;
        function<void(int,int,int,int)> dfs = [&](int pos,int c0,int c1,int c2){
            if(c0>A0||c1>A1||c2>A2) return;
            int rem=N-pos;
            if(c0+rem<A0||c1+rem<A1||c2+rem<A2) return;
            if(pos==N){
                long long sc=0;
                for(int i=0;i<N;i++) sc+=mex2(B[i],B[P[i]]);
                best=max(best,sc);
                return;
            }
            if(c0<A0){B[pos]=0;dfs(pos+1,c0+1,c1,c2);}
            if(c1<A1){B[pos]=1;dfs(pos+1,c0,c1+1,c2);}
            if(c2<A2){B[pos]=2;dfs(pos+1,c0,c1,c2+1);}
        };
        dfs(0,0,0,0);
        cout<<best<<"\n";
    }
}
