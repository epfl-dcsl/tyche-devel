#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef TYCHE_USER_SPACE
#include <stdio.h>
#include <stdlib.h>
#else
#include <linux/kernel.h>
#endif

// ————————————————————————————————— Macros ————————————————————————————————— //
#ifdef TYCHE_USER_SPACE
#define TEST(cond)                                                   \
  do {                                                               \
    if (!(cond)) {                                                   \
      fprintf(stderr, "[%s:%d] %s\n", __FILE__, __LINE__, __func__); \
      abort();                                                       \
    }                                                                \
  } while (0);
#else
#define TEST(cond)                                                                \
  do {                                                                            \
    if (!(cond)) {                                                                \
      printk(KERN_ERR "[%s:%d] %s: cond failed\n", __FILE__, __LINE__, __func__); \
    }                                                                             \
  } while (0);
#endif

#ifdef TYCHE_USER_SPACE
#define LOG(...)                                              \
  do {                                                        \
    printf("[LOG @%s:%d %s] ", __FILE__, __LINE__, __func__); \
    printf(__VA_ARGS__);                                      \
    printf("\n");                                             \
  } while (0);
#else
#define LOG(...)                                                      \
  do {                                                                \
    printk(KERN_NOTICE "[@%s:%d %s] ", __FILE__, __LINE__, __func__); \
    printk(KERN_NOTICE __VA_ARGS__);                                  \
    printk("\n");                                                     \
  } while (0);
#endif

#ifdef TYCHE_DEBUG
#ifdef TYCHE_USER_SPACE
#define DEBUG(...)                                              \
  do {                                                          \
    printf("[DEBUG @%s:%d %s] ", __FILE__, __LINE__, __func__); \
    printf(__VA_ARGS__);                                        \
    printf("\n");                                               \
  } while (0);
#else
#define DEBUG(...)                                                   \
  do {                                                               \
    printk(KERN_DEBUG "[@%s:%d %s] ", __FILE__, __LINE__, __func__); \
    printk(KERN_DEBUG __VA_ARGS__);                                  \
    printk("\n");                                                    \
  } while (0);
#endif
#else
#define DEBUG(...) \
  do {             \
  } while (0);
#endif

#ifdef TYCHE_USER_SPACE
#define WARN(...)                                              \
  do {                                                         \
    printf("[WARN @%s:%d %s] ", __FILE__, __LINE__, __func__); \
    printf(__VA_ARGS__);                                       \
    printf("\n");                                              \
  } while (0);
#else
#define WARN(...)                                                      \
  do {                                                                 \
    printk(KERN_WARNING "[@%s:%d %s] ", __FILE__, __LINE__, __func__); \
    printk(KERN_WARNING __VA_ARGS__);                                  \
    printk("\n");                                                      \
  } while (0);
#endif

#ifdef TYCHE_USER_SPACE
#define ERROR(...)                                              \
  do {                                                          \
    printf("[ERROR @%s:%d %s] ", __FILE__, __LINE__, __func__); \
    printf(__VA_ARGS__);                                        \
    printf("\n");                                               \
  } while (0);
#else
#define ERROR(...)                                                   \
  do {                                                               \
    printk(KERN_ERROR "[@%s:%d %s] ", __FILE__, __LINE__, __func__); \
    printk(KERN_ERROR __VA_ARGS__);                                  \
    printk("\n");                                                    \
  } while (0);
#endif

#endif
