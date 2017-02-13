/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
   vim: set autoindent expandtab shiftwidth=2 softtabstop=2 tabstop=2: */

#include "aqueue.h"
#include <uv.h>
#include <stdlib.h>

#define AQUEUE_MOVE(aqueue, p) do { \
    (p) = ((p) + 1) % (aqueue)->max; \
  } while (0)

struct _AQueue
{
  void     **elements;
  int        max;
  int        head;
  int        tail;
  int        waiting;
  int        length;
  uv_mutex_t mutex;
  uv_cond_t  cond;
};

static int
aqueue_push_unlocked (AQueue *aqueue,
                      void   *element)
{
  if (aqueue->length >= aqueue->max)
    {
      printf ("failed to push because the queue is full (%d)",
               aqueue->max);
      return -1;
    }

  aqueue->elements[aqueue->head] = element;
  AQUEUE_MOVE (aqueue, aqueue->head);
  aqueue->length++;

  return 0;
}

static void *
aqueue_pop_unlocked (AQueue *aqueue)
{
  void *element;

  if (aqueue->length == 0)
    return NULL;

  element = aqueue->elements[aqueue->tail];
  aqueue->elements[aqueue->tail] = NULL;
  AQUEUE_MOVE (aqueue, aqueue->tail);
  aqueue->length--;

  return element;
}

AQueue *
aqueue_new (int max_elements)
{
  AQueue *aqueue;

  if (max_elements <= 0)
    max_elements = 512;

  aqueue = malloc (sizeof (AQueue));
  aqueue->elements = calloc (max_elements, sizeof (void *));
  aqueue->max = max_elements;
  aqueue->head = 0;
  aqueue->tail = 0;
  aqueue->waiting = 0;
  aqueue->length = 0;
  uv_mutex_init (&aqueue->mutex);
  uv_cond_init (&aqueue->cond);

  return aqueue;
}

void
aqueue_destroy (AQueue *aqueue,
                void  (*destroy)(void *element))

{
  if (!aqueue)
    return;

  if (destroy)
    while (!aqueue_is_empty (aqueue))
      {
        void *element;

        element = aqueue_pop (aqueue);
        if (element)
          destroy (element);
      }
  free (aqueue->elements);

  uv_mutex_destroy (&aqueue->mutex);
  uv_cond_destroy (&aqueue->cond);
  free (aqueue);
}

int
aqueue_is_empty (AQueue *aqueue)
{
  int is_empty;

  if (!aqueue)
    return 1;

  uv_mutex_lock (&aqueue->mutex);
  is_empty = aqueue->length == 0;
  uv_mutex_unlock (&aqueue->mutex);

  return is_empty;
}

int
aqueue_get_length (AQueue *aqueue)
{
  int length;

  if (!aqueue)
    return 0;

  uv_mutex_lock (&aqueue->mutex);
  length = aqueue->length;
  uv_mutex_unlock (&aqueue->mutex);

  return length;
}

int
aqueue_push (AQueue *aqueue,
             void   *element)
{
  int ret;

  if (!aqueue)
    return -1;

  uv_mutex_lock (&aqueue->mutex);

  ret = aqueue_push_unlocked (aqueue, element);

  if (aqueue->waiting)
    uv_cond_signal (&aqueue->cond);

  uv_mutex_unlock (&aqueue->mutex);

  return ret;
}

void *
aqueue_pop (AQueue *aqueue)
{
  void *element;

  if (!aqueue)
    return NULL;

  uv_mutex_lock (&aqueue->mutex);

  aqueue->waiting++;
  while (aqueue->length == 0)
    uv_cond_wait (&aqueue->cond, &aqueue->mutex);
  aqueue->waiting--;

  element = aqueue_pop_unlocked (aqueue);

  uv_mutex_unlock (&aqueue->mutex);

  return element;
}

void *
aqueue_try_pop (AQueue *aqueue)
{
  void *element;

  if (!aqueue)
    return NULL;

  uv_mutex_lock (&aqueue->mutex);

  element = aqueue->length > 0 ? aqueue_pop_unlocked (aqueue) : NULL;

  uv_mutex_unlock (&aqueue->mutex);

  return element;
}
