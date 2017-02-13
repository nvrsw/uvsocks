/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
   vim: set autoindent expandtab shiftwidth=2 softtabstop=2 tabstop=2: */

#ifndef __AQUEUE_H__
#define __AQUEUE_H__

typedef struct _AQueue AQueue;

AQueue *
aqueue_new (int max_elements);

void
aqueue_destroy (AQueue *aqueue,
                void  (*destroy) (void *element));

int
aqueue_is_empty (AQueue *aqueue);

int
aqueue_get_length (AQueue *aqueue);

int
aqueue_push (AQueue *aqueue,
             void   *element);
void *
aqueue_pop (AQueue *aqueue);

void *
aqueue_try_pop (AQueue *aqueue);

#endif /* __AQUEUE_H__ */
