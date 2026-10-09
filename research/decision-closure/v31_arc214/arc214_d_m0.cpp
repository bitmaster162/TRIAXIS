#include <bits/stdc++.h>
using namespace std;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N;
    if(!(cin >> N)) return 0;

    long long C[30][30] = {};
    for(int n=0;n<30;n++){
        C[n][0]=C[n][n]=1;
        for(int k=1;k<n;k++) C[n][k]=C[n-1][k-1]+C[n-1][k];
    }

    vector<vector<long long>> P(N+1, vector<long long>(N+1,0));
    vector<vector<long long>> A(N+1, vector<long long>(N+1,0));

    for(int i=N-1;i>=1;i--){
        for(int x=1;x<=N;x++){
            long long g = C[x+i-2][i];
            P[i][x] = g + P[i+1][x-1];
        }
        for(int j=1;j<=N;j++){
            A[i][j] = P[i][j] - P[i][j-1];
        }
    }

    for(int i=1;i<=N;i++){
        for(int j=1;j<=N;j++){
            if(j>1) cout << ' ';
            cout << A[i][j];
        }
        cout << '\n';
    }
    return 0;
}
