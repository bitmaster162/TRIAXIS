#include <bits/stdc++.h>
using namespace std;
using int64 = long long;
static const int MOD = 998244353;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int H,W,T,A,B,C,D;
    cin>>H>>W>>T>>A>>B>>C>>D;
    --A;--B;--C;--D;

    long long S=1LL*H*W;
    vector<int> cur((size_t)S), nxt((size_t)S);
    cur[1LL*A*W+B]=1;

    for(int t=0;t<T;t++){
        fill(nxt.begin(),nxt.end(),0);
        for(int i=0;i<H;i++) for(int j=0;j<W;j++){
            int val=cur[1LL*i*W+j];
            if(!val) continue;
            for(int di=-1;di<=1;di++) for(int dj=-1;dj<=1;dj++){
                if(di==0 && dj==0) continue;
                int ni=i+di,nj=j+dj;
                if(0<=ni && ni<H && 0<=nj && nj<W){
                    int &z=nxt[1LL*ni*W+nj];
                    z += val;
                    if(z>=MOD) z-=MOD;
                }
            }
        }
        cur.swap(nxt);
    }
    cout<<cur[1LL*C*W+D]<<"\n";
    return 0;
}
