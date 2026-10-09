#include <bits/stdc++.h>
using namespace std;
using int64 = long long;
using Mat = vector<vector<int64>>;

static Mat mul(const Mat& A, const Mat& B, int64 mod){
    int n=A.size();
    Mat C(n, vector<int64>(n));
    for(int i=0;i<n;i++){
        for(int k=0;k<n;k++) if(A[i][k]){
            int64 aik=A[i][k];
            for(int j=0;j<n;j++) if(B[k][j]){
                C[i][j]=(C[i][j] + (__int128)aik*B[k][j])%mod;
            }
        }
    }
    return C;
}
static Mat mpow(Mat A, long long e, int64 mod){
    int n=A.size();
    Mat R(n, vector<int64>(n));
    for(int i=0;i<n;i++) R[i][i]=1%mod;
    while(e){
        if(e&1) R=mul(R,A,mod);
        e>>=1;
        if(e) A=mul(A,A,mod);
    }
    return R;
}
int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N; long long p;
    if(!(cin>>N>>p)) return 0;
    Mat A(N, vector<int64>(N));
    long long K=0;
    for(int i=0;i<N;i++) for(int j=0;j<N;j++){
        cin>>A[i][j];
        if(A[i][j]==0) ++K;
    }
    if(p==2){
        Mat B=A;
        for(int i=0;i<N;i++) for(int j=0;j<N;j++) if(B[i][j]==0) B[i][j]=1;
        Mat R=mul(B,B,2);
        for(int i=0;i<N;i++){
            for(int j=0;j<N;j++){
                if(j) cout<<' ';
                cout<<R[i][j];
            }
            cout<<'\n';
        }
        return 0;
    }
    Mat C=A; // zeros already represent 0 in F_p
    Mat R=mpow(C,p,p);

    // A zero self-loop may be used exactly p-1 times; the one remaining
    // step must be a fixed nonzero edge entering or leaving that vertex.
    for(int u=0;u<N;u++) if(A[u][u]==0){
        for(int v=0;v<N;v++) if(v!=u){
            R[u][v]=(R[u][v]+C[u][v])%p;
            R[v][u]=(R[v][u]+C[v][u])%p;
        }
    }
    // For p=3 only, a non-loop zero edge u->v can occur twice in the word,
    // with the unique remaining fixed step v->u between the two copies.
    if(p==3){
        for(int u=0;u<N;u++) for(int v=0;v<N;v++) if(u!=v && A[u][v]==0){
            R[u][v]=(R[u][v]+C[v][u])%p;
        }
    }

    if(K&1){
        for(int i=0;i<N;i++) for(int j=0;j<N;j++)
            if(R[i][j]) R[i][j]=p-R[i][j];
    }
    for(int i=0;i<N;i++){
        for(int j=0;j<N;j++){
            if(j) cout<<' ';
            cout<<R[i][j]%p;
        }
        cout<<'\n';
    }
    return 0;
}
