#include <bits/stdc++.h>
using namespace std;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    if(!(cin>>N)) return 0;
    if(N<=3){
        cout<<"No\n";
        return 0;
    }

    vector<vector<int>> a(N, vector<int>(N,0));

    // Base K4: a proper 3-edge-coloring with colors i xor j.
    // Edge list:
    // 0-1:1, 0-2:2, 0-3:3, 1-2:3, 1-3:2, 2-3:1.
    for(int i=0;i<4;i++) for(int j=i+1;j<4;j++)
        a[i][j]=a[j][i]=(i^j);

    // Inductive extension: all edges incident to the newly added vertex v
    // get the fresh largest label v (labels are 1..v).
    for(int v=4;v<N;v++){
        for(int u=0;u<v;u++) a[u][v]=a[v][u]=v;
    }

    cout<<"Yes\n";
    for(int i=0;i<N;i++){
        for(int j=i+1;j<N;j++){
            if(j>i+1) cout<<' ';
            cout<<a[i][j];
        }
        if(i+1<N) cout<<'\n';
    }
    return 0;
}
