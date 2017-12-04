
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <vector>

struct pq {
  size_t p;
  size_t q;
};

void get_optimized_core_assign_rx(size_t n_port, size_t n_queue, size_t n_thread)
{
  std::vector<pq> vec;
  for (size_t p=0; p<n_port; p++) {
    for (size_t q=0; q<n_queue; q++) {
      vec.push_back({p,q});
    }
  }

  size_t nbq_per_thread = vec.size()/n_thread;
  printf("RX [port:que] pattern\n");
  printf(" nb_q       : %zd \n", vec.size());
  printf(" nb_q/thread: %zd \n", vec.size()/n_thread);

  size_t nb_q = vec.size();
  for (size_t i=0, t=0; i<nb_q; i++) {
    printf(" %zd:%zd -> thread[%zd]\n", vec[i].p, vec[i].q, t);
    if ((i+1)%nbq_per_thread == 0) t++;
  }
}

void get_optimized_core_assign_tx(size_t n_port, size_t n_queue, size_t n_thread)
{
  std::vector<pq> vec;
}

int main(int argc, char** argv)
{
  if (argc < 5) {
    fprintf(stderr, "Usage: %s n_port n_rxq n_txq n_thread\n", argv[0]);
    fprintf(stderr, "  n_port   : 2^i (i=0,1,2,3...)\n");
    fprintf(stderr, "  n_rxq    : 2^i (i=0,1,2,3...)\n");
    fprintf(stderr, "  n_txq    : 2^i (i=0,1,2,3...)\n");
    fprintf(stderr, "  n_thread : 2^i (i=0,1,2,3...)\n");
    return -1;
  }
  const size_t n_port   = atoi(argv[1]);
  const size_t n_rxq    = atoi(argv[2]);
  const size_t n_txq    = atoi(argv[3]);
  const size_t n_thread = atoi(argv[4]);
  printf("n_port  : %zd \n", n_port  );
  printf("n_rxq   : %zd \n", n_rxq   );
  printf("n_txq   : %zd \n", n_txq   );
  printf("n_thread: %zd \n", n_thread);
  printf("\n");

  get_optimized_core_assign_rx(n_port, n_rxq, n_thread);
  get_optimized_core_assign_tx(n_port, n_txq, n_thread);
  return 0;
}

